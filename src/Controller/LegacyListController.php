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
use ErrorException;
use Exception;
use League\Config\Configuration;
use Monolog\Logger;
use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Random\RandomException;
use Slim\App;
use Slim\Views\Twig;

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

  private function authenticate_player(array $data, int|null &$bzid = null): string
  {
    // If either the callsign or password are empty, just bail out here
    if (empty($data['callsign']) || empty($data['password'])) {
      return '';
    }

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
        $statement = $this->pdo->prepare('INSERT INTO auth_tokens (user_id, token, player_ipv4, server_host, server_port) VALUES (:user_id, :token, :player_ipv4, :server_host, :server_port)');
        $statement->bindValue('user_id', $authentication_attempt['bzid'], PDO::PARAM_INT);
        $statement->bindValue('token', $token);
        $statement->bindValue('player_ipv4', $_SERVER['REMOTE_ADDR']);
        $statement->bindValue('server_host', $server_host??null);
        $statement->bindValue('server_port', $server_port??null, PDO::PARAM_INT);
        $statement->execute();
        if (func_num_args() > 1) {
          $bzid = $authentication_attempt['bzid'];
        }
        return "TOKEN: $token\n";
      } catch (RandomException|\PDOException $e) {
        $this->logger->error('Failed to generate authentication token', ['error' => $e->getMessage()]);
        return "NOTOK: Failed to generate token...\n";
      }
    }
  }

  private function create_token(int $bzid, string $server_host = null, int $server_port = null): string|false
  {
    try {
      // Generate a 20 character string for the authentication token. The client/server allocate 22 bytes, including
      // the terminating NUL, for the token.
      $token = bin2hex(random_bytes(10));
      $statement = $this->pdo->prepare('INSERT INTO auth_tokens (user_id, token, player_ipv4, server_host, server_port) VALUES (:user_id, :token, :player_ipv4, :server_host, :server_port)');
      $statement->bindValue('user_id', $bzid, PDO::PARAM_INT);
      $statement->bindValue('token', $token);
      $statement->bindValue('player_ipv4', $_SERVER['REMOTE_ADDR']);
      $statement->bindValue('server_host', $server_host ?? null);
      $statement->bindValue('server_port', $server_port ?? null, PDO::PARAM_INT);
      $statement->execute();
      return $token;
    } catch (RandomException|\PDOException $e) {
      $this->logger->error('Failed to generate authentication token', ['error' => $e->getMessage()]);
      return false;
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
      $server_port = (!empty($data['port'])) ? (int)$data['port'] : 5154;
    }

    // Get the phpbb helper
    $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);

    // Function to split string on CRLF or LF separators and remove empty values
    $split_without_empty = function ($string) {
      return array_filter(explode("\n", str_replace("\r\n", "\n", $string)), function ($v) { return !empty($v); });
    };

    // Take the horrible group list and split it out into an array of groups, removing any empty values
    $groups = $split_without_empty($data['groups'] ?? '');

    // Prepare SQL statements
    try {
      $select_token_statement = $this->pdo->prepare('SELECT player_ipv4, server_host, server_port FROM auth_tokens WHERE user_id = :user_id AND token = :token AND TIMESTAMPDIFF(SECOND, when_created, NOW()) < :token_lifetime');
      $select_token_statement->bindValue('token_lifetime', $this->token_lifetime, PDO::PARAM_INT);
      $delete_token_statement = $this->pdo->prepare('DELETE FROM auth_tokens WHERE user_id = :user_id AND token = :token');
    } catch (\PDOException $e) {
      $this->logger->critical('Failed to prepare one or more statements for processing tokens.', ['error' => $e->getMessage()]);
      return "ERROR: Fatal error when attempting to check tokens.\n";
    }

    // Loop through each token to process
    foreach($split_without_empty($data['checktokens']) as $checktoken) {
      list($remaining, $token_string) = explode('=', $checktoken);
      list($callsign, $player_ipv4) = explode('@', $remaining);

      // If we have both a callsign and a token, process it
      if (!empty($callsign) && !empty($token_string)) {
        // TODO: Does anything even care about this message? Is it just for troubleshooting?
        $return .= "MSG: checktoken callsign=$callsign, ip={$_SERVER['REMOTE_ADDR']}, token=$token_string";
        foreach($groups as $group) {
          $return .= " group=$group";
        }
        $return .= "\n";

        // Try to fetch the user ID for this user
        $user_id = $phpbb->get_user_id_by_username($callsign);

        // If it doesn't exist, identify the user as unregistered and move on
        if ($user_id === null) {
          $return .= "UNK: $callsign\n";
          continue;
        }

        try {
          // Fetch the token information
          $select_token_statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
          $select_token_statement->bindValue('token', $token_string);
          $select_token_statement->execute();
          $token = $select_token_statement->fetch();

          if (!$token) {
            $this->logger->error('Authentication token not found', ['token' => $token_string]);
            $return .= "TOKBAD: $callsign\n";
            continue;
          }

          // Delete the token so it can't be used again
          $delete_token_statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
          $delete_token_statement->bindValue('token', $token_string);
          $delete_token_statement->execute();

          // If the token has a host set, and we have a host to compare it to, check that. This will allow authentication to
          // work in situations where the player IP exposed to the list and the game server differ, such as CGNAT or
          // dual-stack IPv4/6 networks.
          if (!empty($token['server_host']) && !empty($server_host) && $token['server_host'] === $server_host && $token['server_port'] === $server_port) {
            $this->logger->info('Successfully consumed token using host/port match', [
              'callsign' => $callsign,
              'host' => $server_host,
              'port' => $server_port,
            ]);
          }
          // Otherwise, use the old IPv4 comparison check if the token has one
          elseif (!empty($player_ipv4) && $token['player_ipv4'] === $player_ipv4) {
            $this->logger->info('Successfully consumed token using player IPv4 match', [
              'callsign' => $callsign
            ]);
          }
          // Otherwise, fail the authentication attempt
          else {
            $this->logger->error('Authentication token mismatch', [
              'callsign' => $callsign,
              'token_ip' => $token['player_ipv4'],
              'actual_ip' => $player_ipv4,
              'token_host' => $token['server_host'],
              'actual_host' => $server_host,
              'token_port' => $token['server_port'],
              'actual_port' => $server_port
            ]);
            $return .= "TOKBAD: $callsign\n";
            continue;
          }

          $return .= "BZID: $user_id $callsign\nTOKGOOD: $callsign";
          // Check group membership, if the server cares
          if (sizeof($groups) > 0) {
            $player_groups = $phpbb->get_groups_by_user_id($user_id);
            if (!empty($player_groups)) {
              $common_groups = array_intersect($groups, $player_groups);
              if (sizeof($common_groups) > 0) {
                $return .= ':' . implode(':', $common_groups);
              }
            }
          }
          $return .= "\n";
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
    $body = $response->getBody();
    $body->write($this->authenticate_player($data, $bzid));

    if ($bzid) {
      $phpbb_database = $this->config->get('phpbb.database');
      $phpbb_prefix = $this->config->get('phpbb.prefix');
      $sql = "SELECT s.id, s.host, s.port, s.protocol, s.game_info, s.description FROM servers s LEFT JOIN server_advert_groups ag INNER JOIN {$phpbb_database}.{$phpbb_prefix}user_group ug ON ag.group_id = ug.group_id ON s.id = ag.server_id WHERE (ug.user_id = :bzid OR ag.server_id IS NULL)";
    } else {
      $sql = 'SELECT s.id, s.host, s.port, s.protocol, s.game_info, s.description FROM servers s LEFT JOIN server_advert_groups ag ON s.id = ag.server_id WHERE ag.server_id IS NULL';
    }

    if (isset($data['version'])) {
      $sql .= ' AND protocol = :protocol';
    }
    $sta = $this->pdo->prepare($sql);
    if ($bzid) {
      $sta->bindValue('bzid', $bzid);
    }
    if (isset($data['version'])) {
      $sta->bindValue('protocol', $data['version']);
    }
    $sta->execute();
    while($row = $sta->fetch()) {
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
        $sta = $this->pdo->prepare('SELECT id, protocol, hosting_key_id FROM servers WHERE host = :host AND port = :port LIMIT 1');
        $sta->bindValue('host', $hostname);
        $sta->bindValue('port', $port, PDO::PARAM_INT);
        $sta->execute();
        $existing = $sta->fetch();

        // If this server already exists, update it
        if ($existing) {
          if (!empty($hosting_key) && $existing['hosting_key_id'] !== $hosting_key['id']) {
            $errors[] = 'Hosting key mismatch when updating server.';
          } elseif ($existing['protocol'] !== $data['version']) {
            $errors[] = 'Protocol version mismatch when updating server.';
          } else {
            $sta = $this->pdo->prepare("UPDATE servers SET game_info = :game_info, description = :description, when_updated = NOW() WHERE id = :id");
            $sta->bindValue('id', $existing['id'], PDO::PARAM_INT);
            $sta->bindValue('game_info', $data['gameinfo']);
            $sta->bindValue('description', $data['title']);
            $sta->execute();
          }
        } // Otherwise, insert a new server entry
        else {
          $sta = $this->pdo->prepare("INSERT INTO servers (host, port, hosting_key_id, protocol, game_info, description) VALUES (:host, :port, :hosting_key_id, :protocol, :game_info, :description)");
          $sta->bindValue('host', $hostname);
          $sta->bindValue('port', $port, PDO::PARAM_INT);
          $sta->bindValue('hosting_key_id', $hosting_key['id'] ?? null, PDO::PARAM_INT);
          $sta->bindValue('protocol', $data['version']);
          $sta->bindValue('game_info', $data['gameinfo']);
          $sta->bindValue('description', $data['title']);

          if ($sta->execute() && !empty($data['advertgroups'])) {
            $advert_groups = explode(',', $data['advertgroups']);
            if (!empty($advert_groups) && !in_array('EVERYONE', $advert_groups, true)) {
              $server_id = $this->pdo->lastInsertId();
              if (!isset($phpbb)) {
                $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);
              }
              $sta = $this->pdo->prepare('INSERT INTO server_advert_groups (server_id, group_id) VALUES (:server_id, :group_id)');
              $sta->bindValue('server_id', $server_id, PDO::PARAM_INT);
              foreach($advert_groups as $advert_group) {
                $group_id = $phpbb->get_group_id_by_name($advert_group);
                if ($group_id) {
                  $sta->bindValue('group_id', $group_id);
                  $sta->execute();
                }
              }
            }
          }
        }
      } catch(\PDOException $e) {
        $this->logger->error('Database error when adding or updating server.', ['error' => $e->getMessage()]);
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
          $statement->bindValue('id', $server['id'], PDO::PARAM_INT);
          $statement->execute();

          $statement = $this->pdo->prepare('DELETE FROM server_advert_groups WHERE server_id = :server_id');
          $statement->bindValue('server_id', $server['id'], PDO::PARAM_INT);
          $statement->execute();

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

  public function weblogin(Request $request, Response $response, Twig $twig): Response
  {
    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Fetch the color them from the cookie
    $color_theme = (!isset($_COOKIE['color_theme']) || $_COOKIE['color_theme'] !== 'light') ? 'dark' : 'light';

    // Set/update the cookie
    setcookie('color_theme', $color_theme, [
      'expires' => time()+90*86400,
      'samesite' => 'Strict'
    ]);

    // Set up some variables for the view
    $template_variables = [
      'color_theme' => $color_theme,
      'return_url' => $data['url']
    ];

    try {
      // Parse and validate the redirect URL
      $parts = parse_url($data['url']??'');
      if (empty($parts['host']) || empty($parts['scheme'])) {
        throw new ErrorException('A return URL was not provided.');
      }
      if (!isset($parts['port'])) {
        $parts['port'] = ($parts['scheme'] === 'https') ? 443 : 80;
      }

      // Store the hostname for use in the view
      $template_variables['hostname'] = $parts['host'];

      if ($request->getMethod() === 'POST') {
        // Validate CSRF token
        if (false === $request->getAttribute('csrf_status')) {
          throw new Exception('The submitted form was invalid. Please try again.');
        }

        // Error if we don't have a username and password
        if (empty($data['username']) || empty($data['password'])) {
          throw new Exception('Your username and password must be provided.');
        } else {
          // Grab our phpBB helper
          $phpbb = $this->app->getContainer()->get(PHPBBIntegration::class);

          // Attempt to authenticate the player using the provided callsign and password
          $authentication_attempt = $phpbb->authenticate_player($data['username'], $data['password']);
          if (!empty($authentication_attempt['error'])) {
            // TODO: Log error
            throw new Exception($authentication_attempt['error']);
          }

          // Try creating a token
          $token = $this->create_token($authentication_attempt['bzid'], $parts['host'], $parts['port']);
          if ($token === false) {
            throw new Exception('There was an error creating an authentication token.');
          }

          // If we got this far, redirect back to the requesting with along with the token
          return $response
            ->withHeader('Location', str_replace(['%TOKEN%', '%USERNAME%'], [urlencode($token), urlencode($authentication_attempt['callsign'])], $data['url']))
            ->withStatus(302);
        }
      }
    }
    // Unrecoverable errors
    catch (ErrorException $e) {
      $response->getBody()->write($e->getMessage());
      return $response
        ->withHeader('Content-Type', 'text/plain');
    }
    // Errors that should show the login form again
    catch (Exception $e) {
      $template_variables['error'] = $e->getMessage();
    }

    // Render the form
    return $twig->render($response, 'weblogin.html.twig', $template_variables);
  }

  private function usage(Request $request, Response $response): Response
  {
    $response->getBody()->write('Put usage info here');
    return $response;
  }
}
