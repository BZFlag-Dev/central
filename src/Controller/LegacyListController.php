<?php

declare(strict_types=1);

/*
 * BZFlag List Server v3: Handles listing public servers and player authentication
 * Copyright (C) 2023  BZFlag & Associates
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

namespace App\Controller;

use App\Util\PHPBBIntegration;
use App\Util\Valid;
use League\Config\Configuration;
use Monolog\Logger;
use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Random\RandomException;
use Slim\App;

class LegacyListController
{
  private int $token_lifetime;

  public function __construct(private readonly App $app, private readonly PDO $pdo, readonly Configuration $config, readonly Logger $logger)
  {
    $this->token_lifetime = $config->get('token_lifetime');
  }

  public function db(Request $request, Response $response): Response
  {
    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Pick an action, any action, no not that one
    switch($data['action']??'') {
      case 'LIST':
        return $this->list($request, $response, $data);
      case 'GETTOKEN':
        return $this->get_token($request, $response, $data);
      case 'ADD':
        return $this->add_server($request, $response, $data);
      case 'REMOVE':
        return $this->remove_server($request, $response, $data);
      case 'CHECKTOKENS':
        return $this->check_tokens($request, $response, $data);
      default:
        return $this->usage($request, $response);
    }
  }

  private function authenticate_player(array $data): string
  {
    // If either the callsign or password are empty, just bail out here
    if (empty($data['callsign']) || empty($data['password'])) {
      return '';
    }


    // Grab our phpBB helper
    $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);

    // Attempt to authenticate the player using the provided callsign and password
    $authentication_attempt = $phpbb->authenticate_player($data['callsign'], $data['password']);

    // If the authentication failed, throw a NOTOK back
    if (!empty($authentication_attempt['error'])) {
      $this->logger->warning('Authentication failed', [
        'callsign' => $data['callsign'],
        'error' => $authentication_attempt['error']
      ]);
      return "NOTOK: {$authentication_attempt['error']}\n";
    }
    // Otherwise, let's generate, store, and return a token
    else {
      try {
        // Generate a 20 character string for the authentication token. The client/server allocate 22 bytes, including
        // the terminating NUL, for the token.
        $token = bin2hex(random_bytes(10));
        // TODO: Save the server host/port if provided
        $statement = $this->pdo->prepare('INSERT INTO auth_tokens (user_id, token, player_ipv4) VALUES (:user_id, :token, :player_ipv4)');
        $statement->bindParam('user_id', $authentication_attempt['bzid'], PDO::PARAM_INT);
        $statement->bindParam('token', $token);
        $statement->bindParam('player_ipv4', $_SERVER['REMOTE_ADDR']);
        $statement->execute();
        return "TOKEN: $token\n";
      } catch (RandomException|\PDOException $e) {
        $this->logger->error('Failed to generate authentication token', ['error' => $e->getMessage()]);
        return "NOTOK: Failed to generate token...\n";
      }
    }
  }

  private function process_tokens(array $data): string
  {
    // Information to return
    $return = '';

    // Split nameport into host and port parts
    // TODO: Test if $server_host isn't defined by the below
    if (!empty($data['nameport'])) {
      $parts = parse_url("bzfs://{$data['nameport']}");
      // If the host/port is seriously malformed, just nuke the value
      if ($parts === false) {
        unset($data['nameport']);
      } else {
        $server_host = $parts['host'];
        $server_port = $parts['port'] ?? 5154;
      }
      unset($parts);
    } elseif (!empty($data['host'])) {
      $server_host = $data['host'];
      $server_port = $data['port'] ?? 5154;
    }

    // Get the phpbb helper
    $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);

    // Function to split string on CRLF or LF separators and remove empty values
    $split_without_empty = function ($string) {
      return array_filter(explode("\n", str_replace("\r\n", "\n", $string)), function ($v) { return !empty($v); });
    };

    // Take the horrible group list and split it out into an array of groups, removing any empty values
    $groups = $split_without_empty($data['groups'] ?? '');

    // Loop through each token to process
    foreach($split_without_empty($data['checktokens']) as $checktoken) {
      list($remaining, $token_string) = explode('=', $checktoken);
      list($callsign, $player_ipv4) = explode('@', $remaining);

      // If we have both a callsign and a token, process it
      if (!empty($callsign) && !empty($token_string)) {
        // Try to fetch the user ID for this user
        $user_id = $phpbb->get_user_id_by_username($callsign);

        // If it doesn't exist, identify the user as unregistered and move on
        if ($user_id === null) {
          $return .= "UNK: $callsign\n";
          continue;
        }

        try {
          $statement = $this->pdo->prepare('SELECT player_ipv4, server_host, server_port FROM auth_tokens WHERE user_id = :user_id AND token = :token AND TIMESTAMPDIFF(SECOND, when_created, NOW()) < :token_lifetime');
          $statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
          $statement->bindValue('token', $token_string);
          $statement->bindValue('token_lifetime', $this->token_lifetime, PDO::PARAM_INT);
          $statement->execute();
          $token = $statement->fetch();

          if (!$token) {
            $this->logger->error('Authentication token not found', ['token' => $token_string]);
            $return .= "TOKBAD: $callsign\n";
            continue;
          }

          // If the token has a host set, and we have a host to compare it to, check that. This will allow authentication to
          // work in situations where the player IP exposed to the list and the game server differ, such as CGNAT or
          // dual-stack IPv4/6 networks.
          if (!empty($token['server_host']) && !empty($server_host) && !($token['server_host'] === $server_host && $token['server_port'] === $server_port)) {
            $this->logger->error('Authentication token server host or port mismatch', [
              'token_host' => $token['server_host'],
              'actual_host' => $server_host,
              'token_port' => $token['server_port'],
              'actual_port' => $server_port
            ]);
            $return .= "TOKBAD: $callsign\n";
            continue;
          }
          // Otherwise, use the old IPv4 comparison check if the token has one
          // TODO: Should auth fail here if the token does not have an IP saved?
          elseif (!empty($player_ipv4) && $token['player_ipv4'] !== $player_ipv4) {
            $this->logger->error('Authentication token player IP mismatch', [
              'token_ip' => $token['player_ipv4'],
              'actual_ip' => $player_ipv4
            ]);
            $return .= "TOKBAD: $callsign\n";
            continue;
          }

          // TODO: Check group membership

          $return .= "BZID: $user_id $callsign\nTOKGOOD: $callsign\n";
        } catch (\PDOException $e) {
          $this->logger('Database error reading token', ['token' => $token, 'user_id' => $user_id]);
          $return .= "TOKBAD: $callsign\n";
        }
      }
    }

    return $return;
  }

  private function split_nameport($nameport): array
  {
    // Default to port 5154
    $port = '5154';

    $colonPos = strrpos($nameport, ':');
    // If there isn't a port in the public address, assume it's just a hostname
    if ($colonPos === false) {
      $hostname = $nameport;
    } else {
      $hostname = substr($nameport, 0, $colonPos);
      $port = substr($nameport, $colonPos + 1);
    }

    return [$hostname, $port];
  }

  private function dns_has_ip($host, $ip): bool
  {
    // If the host is actually an IPv4 address, just compare that to the passed in IP.
    if (filter_var($host, FILTER_VALIDATE_IP, ['flags' => FILTER_FLAG_IPV4])) {
      return $host === $ip;
    }

    $dns = dns_get_record($host, DNS_A|DNS_AAAA);
    foreach($dns as $record) {
      if (($record['type'] === 'A' && $record['ip'] === $ip) || ($record['type'] === 'AAAA' && $record['ipv6'] === $ip)) {
        return true;
      }
    }

    return false;
  }

  private function list(Request $request, Response $response, array $data): Response
  {
    $sql = 'SELECT id, host, port, protocol, game_info, description, has_advert_groups FROM servers';
    if (isset($data['version'])) {
      $sql .= ' WHERE protocol = :protocol';
    }
    $sta = $this->pdo->prepare($sql);
    if (isset($data['version'])) {
      $sta->bindValue('protocol', $data['version']);
    }
    $sta->execute();
    $body = $response->getBody();
    $body->write($this->authenticate_player($data));
    while($row = $sta->fetch()) {
      // TODO: Support advert groups. For now just hide servers that *have* advert groups.
      if ($row['has_advert_groups']) {
        continue;
      }
      $body->write("{$row['host']}:{$row['port']} {$row['protocol']} {$row['game_info']} 127.0.0.1 {$row['description']}\n");
    }

    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function get_token(Request $request, Response $response, array $data): Response
  {
    $response->getBody()->write($this->authenticate_player($data));
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function add_server(Request $request, Response $response, array $data): Response
  {
    // Validate the provided values
    $errors = [];

    // Name/port
    $hostname = '';
    $port = '5154';
    if (empty($data['nameport'])) {
      $errors[] = 'Missing public address.';
    } else {
      $colonPos = strrpos($data['nameport'], ':');
      // If there isn't a port in the public address, assume it's just a hostname
      if ($colonPos === false) {
        $hostname = $data['nameport'];
      } else {
        $hostname = substr($data['nameport'], 0, $colonPos);
        $port = substr($data['nameport'], $colonPos + 1);
      }

      // Validate the provided values
      if (!Valid::serverHostname($hostname)) {
        $errors[] = 'Invalid hostname in public address.';
      }
      if (!Valid::serverPort($port)) {
        $errors[] = 'Invalid port in public address.';
      }
    }

    // Protocol version
    if (empty($data['version']) || !Valid::serverProtocol($data['version'])) {
      $errors[] = 'Missing or invalid protocol version.';
    }

    // Game information
    if (empty($data['gameinfo']) || !Valid::serverGameInfo($data['gameinfo'])) {
      $errors[] = 'Missing or invalid game info.';
    }

    // Server description (optional, so only check if not empty)
    if (empty($data['title'])) {
      $data['title'] = '';
    } elseif (!Valid::serverDescription($data['title'])) {
      $errors[] = 'Invalid server description.';
    }

    // Check if the provided server token allows manipulating this hostname (not required for protocol versions
    // 'BZFS1910' [1.10] or 'BZFS0026' [2.0])
    if (empty($errors) && !in_array($data['version'], ['BZFS1910', 'BZFS0026'], true)) {
      // If a key is required, but none were provided...
      if (empty($data['key'])) {
        $errors[] = 'Missing server authentication key.';
      } else {
        try {
          $statement = $this->pdo->prepare('SELECT id, host, user_id FROM hosting_keys WHERE key_string = :key_string');
          $statement->bindValue('key_string', $data['key']);
          $statement->execute();
          $hosting_key = $statement->fetch();
          if (!$hosting_key) {
            $errors[] = 'Invalid server authentication key.';
          } else {
            // The host on the key must exactly match the public address
            if (strcasecmp($hosting_key['host'], $hostname) !== 0) {
              $errors[] = "Host mismatch for server authentication key.";
            } else {
              // Get the phpbb helper
              $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);

              // Attempt to get the server owner name
              $server_owner = $phpbb->get_username_by_user_id($hosting_key['user_id']);
            }
          }
        } catch (\PDOException $e) {
          // TODO: Log failure
        }
      }
    }

    // If we have no errors up to this point, add the server
    if (empty($errors)) {
      try {
        // Check if the server already exists
        $sta = $this->pdo->prepare('SELECT id, hosting_key_id FROM servers WHERE host = :host AND port = :port LIMIT 1');
        $sta->bindValue('host', $hostname);
        $sta->bindValue('port', $port, PDO::PARAM_INT);
        $sta->execute();
        $existing = $sta->fetch();

        // If this server already exists, update it
        // TODO: Support advert groups
        if ($existing) {
          if (!empty($hosting_key) && $existing['hosting_key_id'] !== $hosting_key['id']) {
            $errors[] = 'Hosting key mismatch when updating server';
          } else {
            $sta = $this->pdo->prepare("UPDATE servers SET protocol = :protocol, game_info = :game_info, description = :description, has_advert_groups = :has_advert_groups, when_updated = NOW() WHERE id = :id");
            $sta->bindValue('id', $existing['id'], PDO::PARAM_INT);
            $sta->bindValue('protocol', $data['version']);
            $sta->bindValue('game_info', $data['gameinfo']);
            $sta->bindValue('description', $data['title']);
            $sta->bindValue('has_advert_groups', 0);
            $sta->execute();
          }
        } // Otherwise, insert a new server entry
        else {
          $sta = $this->pdo->prepare("INSERT INTO servers (host, port, hosting_key_id, protocol, game_info, description, has_advert_groups) VALUES (:host, :port, :hosting_key_id, :protocol, :game_info, :description, :has_advert_groups)");
          $sta->bindValue('host', $hostname);
          $sta->bindValue('port', $port, PDO::PARAM_INT);
          $sta->bindValue('hosting_key_id', $hosting_key['id'] ?? null, PDO::PARAM_INT);
          $sta->bindValue('protocol', $data['version']);
          $sta->bindValue('game_info', $data['gameinfo']);
          $sta->bindValue('description', $data['title']);
          $sta->bindValue('has_advert_groups', 0);
          $sta->execute();
        }
      } catch(\PDOException $e) {
        // TODO: Log errors
        $errors[] = 'Database error when adding or updating the server.';
      }
    }

    // If we had any errors, report them
    if (!empty($errors)) {
      $response->getBody()->write('ERROR: '.implode(' ', $errors) . "\n");
      return $response
        ->withHeader('Content-Type', 'text/plain');
    }
    // Otherwise, tell the server it was added and process any tokens
    else {
      $response->getBody()->write("ADD: $hostname:$port\n");

      // Process tokens
      $response->getBody()->write($this->process_tokens($data));
      return $response
        ->withHeader('Content-Type', 'text/plain');
    }
  }

  private function remove_server(Request $request, Response $response, array $data): Response
  {
    $errors = [];

    // Name/port
    $port = '5154';
    if (empty($data['nameport'])) {
      $errors[] = 'Missing public address.';
    } else {
      $response->getBody()->write("MSG: REMOVE request from {$data['nameport']}\n");
      $colonPos = strrpos($data['nameport'], ':');
      // If there isn't a port in the public address, assume it's just a hostname
      if ($colonPos === false) {
        $hostname = $data['nameport'];
      } else {
        $hostname = substr($data['nameport'], 0, $colonPos);
        $port = substr($data['nameport'], $colonPos + 1);
      }

      // Validate the provided values
      if (!Valid::serverHostname($hostname)) {
        $errors[] = 'Invalid hostname in public address.';
      }
      if (!Valid::serverPort($port)) {
        $errors[] = 'Invalid port in public address.';
      }
    }

    if (empty($errors)) {
      // Fetch information about this server
      try {
        $statement = $this->pdo->prepare('SELECT s.id, h.key_string FROM servers s LEFT JOIN hosting_keys h ON s.hosting_key_id = h.id WHERE s.host = :host AND s.port = :port');
        $statement->bindValue('host', $hostname);
        $statement->bindValue('port', $port, PDO::PARAM_INT);
        $statement->execute();
        $server = $statement->fetch();
      } catch(\PDOException $e) {
        // TODO: Log failure
        $errors[] = 'Failed to lookup server. '.$e->getMessage();
      }
    }

    // If the server exists, let's decide if we allow the removal
    if (!empty($server)) {
      // If a key is provided, and it's the same as the one used for listing the server, we can skip the IP check
      if ((!empty($data['key']) && $data['key'] === $server['key_string']) || $this->dns_has_ip($hostname, $_SERVER['REMOTE_ADDR'])) {
        try {
          $statement = $this->pdo->prepare('DELETE FROM servers WHERE id = :id LIMIT 1');
          $statement->bindValue('id', $server['id']);
          $statement->execute();

          // TODO: Delete advert groups for this server

          $response->getBody()->write("REMOVE: {$data['nameport']}\n");
        } catch (\PDOException $e) {
          // TODO: Log failure
          $errors[] = 'Failed to remove server.';
        }
      } else {
        // TODO: Log mismatch
        $errors[] = "Requesting address {$_SERVER['REMOTE_ADDR']} is not in the resolved hostname.";
      }
    }

    if (!empty($errors)) {
      $response->getBody()->write('ERROR: ' . implode(' ', $errors) . "\n");
    }
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function check_tokens(Request $request, Response $response, array $data): Response
  {
    // Process tokens
    $response->getBody()->write($this->process_tokens($data));
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function usage(Request $request, Response $response): Response
  {
    $response->getBody()->write('Put usage info here');
    return $response;
  }
}
