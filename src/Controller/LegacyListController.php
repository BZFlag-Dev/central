<?php

declare(strict_types=1);

/*
 * BZFlag List Server v3: Handles listing public servers and player authentication
 * Copyright (C) 2023-2024  BZFlag & Associates
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

use App\DatabaseHelper\GameServerHelper;
use App\DatabaseHelper\HostingKeysHelper;
use App\DatabaseHelper\TokenHelper;
use App\Misc\BZFlagServer;
use App\Util\PHPBBIntegration;
use App\Util\Valid;
use ErrorException;
use Exception;
use Monolog\Logger;
use PDOException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Views\Twig;

readonly class LegacyListController
{
  public function __construct(private App $app, private PHPBBIntegration $phpbb, private Logger $logger)
  {
  }

  public function db(Request $request, Response $response): Response
  {
    // Ensure that only IPv4 clients can access this in case of misconfiguration or someone modifying their hosts file
    if (filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, ['flags' => FILTER_FLAG_IPV4]) === false) {
      $response->getBody()->write("ERROR: The legacy bzfls can only be accessed over IPv4\n");
      return $response
        ->withHeader('Content-Type', 'text/plain')
        ->withStatus(400);
    }

    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Pick an action, any action, no not that one
    return match ($data['action'] ?? '') {
      'LIST' => $this->list($response, $data),
      'GETTOKEN' => $this->get_token($response, $data),
      'ADD' => $this->add_server($response, $data),
      'REMOVE' => $this->remove_server($response, $data),
      'CHECKTOKENS' => $this->check_tokens($response, $data),
      default => $this->usage($response),
    };
  }

  private function authenticate_player(array $data, $skip_token = false, int|null &$bzid = null): string
  {
    // If either the callsign or password are empty, just bail out here
    if (empty($data['callsign']) || empty($data['password'])) {
      return '';
    }

    // Split nameport into host and port parts
    if (!empty($data['nameport'])) {
      try {
        [$server_host, $server_port] = $this->split_nameport($data['nameport']);
      } catch (Exception) {
      }
    }

    // Attempt to authenticate the player using the provided callsign and password
    $authentication_attempt = $this->phpbb->authenticate_player($data['callsign'], $data['password']);

    // If the authentication failed, throw a NOTOK back
    if (!empty($authentication_attempt['error'])) {
      $this->logger->warning('Authentication failed', [
        'callsign' => $data['callsign'],
        'error' => $authentication_attempt['error']
      ]);
      return "NOTOK: {$authentication_attempt['error']}\n";
    }

    // Pass the BZID back if requested
    if (func_num_args() >= 3) {
      $bzid = $authentication_attempt['bzid'];
    }

    // Unless we're told to skip it, let's generate, store, and return a token
    if (!$skip_token) {
      /**
       * @var TokenHelper $token_helper
       */
      $token_helper = $this->app->getContainer()->get(TokenHelper::class);

      // Create a token
      $token = $token_helper->create(
        bzid: $authentication_attempt['bzid'],
        player_ipv4: $_SERVER['REMOTE_ADDR'],
        server_host: $server_host ?? null,
        server_port: $server_port ?? null
      );

      if ($token !== null) {
        return "TOKEN: $token\n";
      } else {
        return "NOTOK: Failed to generate token...\n";
      }
    }

    return '';
  }

  private function process_tokens(array $data): string
  {
    if (!isset($data['checktokens'])) {
      return '';
    }

    /**
     * @var TokenHelper $token_helper
     */
    $token_helper = $this->app->getContainer()->get(TokenHelper::class);

    // Delete stale tokens
    $token_helper->delete_stale();

    // Information to return
    $return = '';

    // Split nameport into host and port parts
    if (!empty($data['nameport'])) {
      try {
        [$server_host, $server_port] = $this->split_nameport($data['nameport']);
      } catch (Exception) {
      }
    }

    // Function to split string on CRLF or LF separators and remove empty values
    $split_without_empty = function ($string) {
      return array_filter(explode("\n", str_replace("\r\n", "\n", $string)), function ($v) { return !empty($v); });
    };

    // Take the horrible group list and split it out into an array of groups, removing any empty values
    $groups = $split_without_empty($data['groups'] ?? '');

    // Loop through each token to process
    foreach($split_without_empty($data['checktokens']) as $checktoken) {
      list($remaining, $token) = explode('=', $checktoken);
      list($callsign, $player_ipv4) = explode('@', $remaining);

      // If we have both a callsign and a token, process it
      if (!empty($callsign) && !empty($token)) {
        // TODO: Does anything even care about this message? Is it just for troubleshooting?
        $return .= "MSG: checktoken callsign=$callsign, ip={$_SERVER['REMOTE_ADDR']}, token=$token";
        foreach($groups as $group) {
          $return .= " group=$group";
        }
        $return .= "\n";

        // Try to fetch the user ID for this user
        $user_id = $this->phpbb->get_user_id_by_username($callsign);

        // If it doesn't exist, identify the user as unregistered and move on
        if ($user_id === null) {
          $return .= "UNK: $callsign\n";
          continue;
        }

        // If a token wasn't provided, don't even bother checking the database
        if ($token === 'NONE') {
          $return .= "TOKBAD: $callsign\n";
          continue;
        }

        if ($token_helper->validate($callsign, $user_id, $token, $player_ipv4, $server_host ?? null, $server_port ?? null)) {
          $return .= "BZID: $user_id $callsign\nTOKGOOD: $callsign";
        } else {
          $return .= "TOKBAD: $callsign\n";
        }

        // Check group membership, if the server cares
        if (sizeof($groups) > 0) {
          $player_groups = $this->phpbb->get_groups_by_user_id($user_id);
          if (!empty($player_groups)) {
            $common_groups = array_intersect($groups, $player_groups);
            if (sizeof($common_groups) > 0) {
              $return .= ':' . implode(':', $common_groups);
            }
          }
        }
        $return .= "\n";
      }
    }

    return $return;
  }

  /**
   * @throws Exception
   */
  private function split_nameport($nameport): array
  {
    // Split the nameport into parts
    $parts = parse_url("bzfs://$nameport");

    // If the host/port is seriously malformed, throw an exception
    if ($parts === false) {
      throw new Exception('Unable to parse nameport.');
    }
    foreach(array_keys($parts) as $key) {
      if (!in_array($key, ['scheme', 'host', 'port'], true)) {
        throw new Exception('Invalid nameport value.');
      }
    }

    if (!isset($parts['host']) || !Valid::serverHostname($parts['host'])) {
      throw new Exception('Invalid hostname in public address.');
    }

    if (isset($parts['port']) && !Valid::serverPort($parts['port'])) {
      throw new Exception('Invalid port in public address.');
    }

    return [$parts['host'], $parts['port'] ?? 5154];
  }

  private function dns_has_ip($host, $ip): bool
  {
    // If the host is actually an IPv4 address, just compare that to the passed in IP.
    if (filter_var($host, FILTER_VALIDATE_IP, ['flags' => FILTER_FLAG_IPV4]) !== false) {
      return $host === $ip;
    }

    $dns = dns_get_record($host, DNS_A | DNS_AAAA);
    foreach($dns as $record) {
      if (($record['type'] === 'A' && $record['ip'] === $ip) || ($record['type'] === 'AAAA' && $record['ipv6'] === $ip)) {
        return true;
      }
    }

    return false;
  }

  private function list(Response $response, array $data): Response
  {
    $body = $response->getBody();

    // Default to the plain list format
    if (!isset($data['listformat']) || !in_array($data['listformat'], ['plain', 'json', 'lua'], true)) {
      $data['listformat'] = 'plain';
    }

    // Handle authentication for the plain type only
    if ($data['listformat'] === 'plain') {
      // Authenticate the player
      $auth = $this->authenticate_player($data, isset($data['skiptoken']) && $data['skiptoken'] === '1', $user_id);
      $body->write($auth);

      // If the login was successful, check if the user has any unread private messages
      if ($user_id > 0) {
        $pm_count = $this->phpbb->get_private_message_count_by_user_id($user_id);
        if ($pm_count > 0) {
          $body->write("NOTICE: You have $pm_count messages waiting for you, {$data['callsign']}. Log in at https://forums.bzflag.org/ to read them.\n");
        }
      }
    }

    /**
     * @var GameServerHelper $game_servers_helper
     */
    $game_servers_helper = $this->app->getContainer()->get(GameServerHelper::class);

    // Fetch the servers
    $servers = $game_servers_helper->get_many(
      protocol: $data['version'] ?? null,
      user_id: $user_id ?? null,
    );

    if ($data['listformat'] === 'lua') {
      $body->write("return {\n");
      $body->write("fields = { 'version', 'hexcode', 'addr', 'ipaddr', 'title', 'owner' },\n");
      $body->write("servers = {\n");
      foreach ($servers as $server) {
        $body->write("{\"" . addslashes($server['protocol']) . "\",\"" . addslashes($server['game_info']) . "\",\"" . addslashes("{$server['hostname']}:{$server['port']}") . "\",\"127.0.0.1\",\"" . addslashes($server['description'] ?? '') . "\",\"" . addslashes($server['owner'] ?? '') . "\"},\n");
      }
      $body->write("}\n}\n");
    } elseif ($data['listformat'] === 'json') {
      $body->write("{\n");
      $body->write("\"fields\": [\"version\",\"hexcode\",\"addr\",\"ipaddr\",\"title\",\"owner\"],\n");
      $body->write("\"servers\": [");
      $first = true;
      foreach($servers as $server) {
        if ($first) {
          $first = false;
        } else {
          $body->write(",");
        }
        $body->write("\n[\"" . addslashes($server['protocol']) . "\",\"" . addslashes($server['game_info']) . "\",\"" . addslashes("{$server['hostname']}:{$server['port']}") . "\",\"127.0.0.1\",\"" . addslashes($server['description'] ?? '') . "\",\"" . addslashes($server['owner'] ?? '') . "\"]");
      }
      $body->write("\n]\n}\n");
    } else {
      foreach($servers as $server) {
        $body->write("{$server['hostname']}:{$server['port']} {$server['protocol']} {$server['game_info']} 127.0.0.1 {$server['description']}\n");
      }
    }

    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function get_token(Response $response, array $data): Response
  {
    $response->getBody()->write($this->authenticate_player($data));
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function add_server(Response $response, array $data): Response
  {
    // Validate the provided values
    $errors = [];

    // Name/port
    if (empty($data['nameport'])) {
      $errors[] = 'Missing public address.';
    } else {
      try {
        list($hostname, $port) = $this->split_nameport($data['nameport']);
      } catch (Exception $e) {
        $errors[] = $e->getMessage();
      }
    }

    // Verify that the IP of this HTTP requests is contained in the DNS response of the hostname
    if (!empty($hostname) && !$this->dns_has_ip($hostname, $_SERVER['REMOTE_ADDR'])) {
      $errors[] = 'Specified hostname does not contain the the requesting address.';
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
          /**
           * @var HostingKeysHelper $hosting_key_helper
           */
          $hosting_key_helper = $this->app->getContainer()->get(HostingKeysHelper::class);

          $hosting_key = $hosting_key_helper->get_one_by_key($data['key']);

          if ($hosting_key === null) {
            $errors[] = 'Invalid server authentication key.';
          } else {
            // The host on the key must exactly match the public address
            if (strcasecmp($hosting_key['host'], $hostname) !== 0) {
              $errors[] = "Host mismatch for server authentication key.";
            } else {


              // Attempt to get the server owner name
              $server_owner = $this->phpbb->get_username_by_user_id($hosting_key['user_id']);

              // If the owner lookup failed, error
              if (!$server_owner) {
                $errors[] = 'Owner lookup failure';
              }
            }
          }
        } catch (PDOException $e) {
          $errors[] = 'Owner lookup failure';
          $this->logger->error('Server owner lookup failure', ['error' => $e->getMessage()]);
        }
      }
    }

    // Verify that we can connect to the server
    if (empty($errors)) {
      try {
        new BZFlagServer($hostname, $port, $data['version']);
      } catch (Exception $e) {
        $this->logger->error($e->getMessage(), [
          'hostname' => $hostname,
          'port' => $port,
          'protocol' => $data['version']
        ]);
        $errors[] = 'Failed to connect to or verify running server.';
      }
    }

    // If we have no errors up to this point, add the server
    if (empty($errors)) {
      /**
       * @var GameServerHelper $game_server_helper
       */
      $game_server_helper = $this->app->getContainer()->get(GameServerHelper::class);

      // Check if the server already exists
      $existing = $game_server_helper->get_info_from_host_and_port($hostname, $port);

      // If this server already exists, update it
      if ($existing) {
        if (!empty($hosting_key) && $existing['hosting_key_id'] !== $hosting_key['id']) {
          $errors[] = 'Hosting key mismatch when updating server.';
        } elseif ($existing['protocol'] !== $data['version']) {
          $errors[] = 'Protocol version mismatch when updating server.';
        } else {
          $args = [
            'id' => $existing['id'],
            'game_info' => $data['gameinfo'],
            'description' => $data['title']
          ];
          if ($server_owner) {
            $args['owner'] = $server_owner;
          }

          if (!$game_server_helper->update(...$args)) {
            $errors[] = 'Failed to update server.';
          }
        }
      } // Otherwise, insert a new server entry
      else {
        $args = [
          'protocol' => $data['version'],
          'host' => $hostname,
          'port' => $port,
          'game_info' => $data['gameinfo'],
          'description' => $data['title']
        ];
        if ($hosting_key['id']) {
          $args['hosting_key_id'] = $hosting_key['id'];
        }
        if ($server_owner) {
          $args['owner'] = $server_owner;
        }
        if ($data['build']) {
          $args['build'] = $data['build'];
        }

        // Try creating the server
        $server_id = $game_server_helper->create(...$args);
        if ($server_id === false) {
          $errors[] = 'Failed to create server.';
        } else {
          // If the server was added, and we have advert groups, associate them with the server
          if (!empty($data['advertgroups'])) {
            // Split the comma separated list of groups
            $advert_groups = explode(',', $data['advertgroups']);

            // Ensure the list isn't empty and that it doesn't contain the EVERYONE group
            if (!empty($advert_groups) && !in_array('EVERYONE', $advert_groups, true)) {
              // Look up the group IDs and populate a list
              $group_ids = [];
              foreach ($advert_groups as $advert_group) {
                $group_id = $this->phpbb->get_group_id_by_name($advert_group);
                if ($group_id) {
                  $group_ids[] = $group_id;
                }
              }

              // If we have some valid groups, create the advert groups
              if (sizeof($group_ids) > 0) {
                $game_server_helper->create_advert_groups($server_id, $group_ids);
              }
            }
          }
        }
      }
    }

    // If we had any errors, report them
    if (!empty($errors)) {
      $response->getBody()->write('ERROR: '.implode(' ', $errors) . "\n");
    }
    // Otherwise, tell the server it was added and process any tokens
    else {
      $body = $response->getBody();

      // Write out the server owner, if there is one
      if (!empty($server_owner)) {
        $body->write("OWNER: $server_owner\n");
      }

      // Write out a confirmation that the server was added
      $body->write("ADD: $hostname:$port\n");

      // Process tokens
      $body->write($this->process_tokens($data));
    }

    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function remove_server(Response $response, array $data): Response
  {
    $errors = [];

    // Name/port
    if (empty($data['nameport'])) {
      $errors[] = 'Missing public address.';
    } else {
      try {
        list($hostname, $port) = $this->split_nameport($data['nameport']);
      } catch (Exception $e) {
        $errors[] = $e->getMessage();
      }
    }

    if (empty($errors)) {
      /**
       * @var GameServerHelper $game_server_helper
       */
      $game_server_helper = $this->app->getContainer()->get(GameServerHelper::class);

      // Fetch information about this server
      $server = $game_server_helper->get_info_from_host_and_port($hostname, $port);

      // If the server exists, let's decide if we allow the removal
      if ($server) {
        // If a key is provided, and it's the same as the one used for listing the server, we can skip the IP check
        if ((!empty($data['key']) && $data['key'] === $server['key_string']) || $this->dns_has_ip($hostname, $_SERVER['REMOTE_ADDR'])) {
          // Delete the server
          if ($game_server_helper->delete($server['id'])) {
            $response->getBody()->write("REMOVE: {$data['nameport']}\n");
          } else {
            $errors[] = 'Failed to remove server.';
          }
        } else {
          $errors[] = "Requesting address {$_SERVER['REMOTE_ADDR']} is not in the resolved hostname.";
          $this->logger->error('Request to remove server came from IP address that is not in resolved hostname', ['remote_addr' => $_SERVER['REMOTE_ADDR'], 'hostname' => $hostname]);
        }
      } else {
        $errors[] = 'Server not found.';
      }
    }

    // If there were errors, write those out
    if (!empty($errors)) {
      $response->getBody()->write('ERROR: ' . implode(' ', $errors) . "\n");
    }
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function check_tokens(Response $response, array $data): Response
  {
    // Process tokens
    $response->getBody()->write($this->process_tokens($data));
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function usage(Response $response): Response
  {
    /**
     * @var Twig $twig
     */
    $twig = $this->app->getContainer()->get(Twig::class);

    return $twig->render($response, 'legacy_usage.html.twig');
  }

  public function weblogin(Request $request, Response $response, Twig $twig): Response
  {
    // Ensure that only IPv4 clients can access this in case of misconfiguration or someone modifying their hosts file
    if (filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, ['flags' => FILTER_FLAG_IPV4]) === false) {
      $response->getBody()->write("ERROR: The legacy weblogin can only be accessed over IPv4\n");
      return $response
        ->withHeader('Content-Type', 'text/plain')
        ->withStatus(400);
    }

    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Fetch the color them from the cookie
    $color_theme = (!isset($_COOKIE['color_theme']) || $_COOKIE['color_theme'] !== 'light') ? 'dark' : 'light';

    // Set/update the cookie
    setcookie('color_theme', $color_theme, [
      'expires' => time() + 90 * 86400,
      'samesite' => 'Strict'
    ]);

    // Set up some variables for the view
    $template_variables = [
      'color_theme' => $color_theme,
      'return_url' => $data['url']
    ];

    try {
      // Parse and validate the redirect URL
      $parts = parse_url($data['url'] ?? '');
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
          // Attempt to authenticate the player using the provided callsign and password
          $authentication_attempt = $this->phpbb->authenticate_player($data['username'], $data['password']);
          if (!empty($authentication_attempt['error'])) {
            $this->logger->error('Player authentication failure', ['error' => $authentication_attempt['error']]);
            throw new Exception($authentication_attempt['error']);
          }

          /**
           * @var TokenHelper $token_helper
           */
          $token_helper = $this->app->getContainer()->get(TokenHelper::class);

          // Try creating a token
          $token = $token_helper->create(
            bzid: $authentication_attempt['bzid'],
            server_host: $parts['host'],
            server_port: $parts['port']
          );

          if ($token === null) {
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

  public function listkeys(Request $request, Response $response, Twig $twig, HostingKeysHelper $hosting_key_helper): Response
  {
    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Grab a copy of the action
    $action = $data['action'] ?? '';

    // Limit the session length to 30 minutes
    $session_lifespan_minutes = 30;

    if ($request->getMethod() === 'POST') {
      // Validate CSRF token
      if (false === $request->getAttribute('csrf_status')) {
        $_SESSION['listkeys_flash'] = 'The submitted form was invalid. Please try again.';
      }

      // If the user is trying to log in, process that
      elseif ($action === 'login') {
        // Attempt the login
        $authentication_attempt = $this->phpbb->authenticate_player($data['username'], $data['password']);

        // If it failed, set a flash message
        if (!empty($authentication_attempt['error'])) {
          $_SESSION['listkeys_flash'] = "Authentication failed: {$authentication_attempt['error']}";
        }
        // Otherwise, store the session info
        else {
          $_SESSION['listkeys_bzid'] = $authentication_attempt['bzid'];
          $_SESSION['listkeys_username'] = $authentication_attempt['callsign'];
          $_SESSION['listkeys_session_created'] = time();
        }
      }

      // If a BZID isn't stored in the session or the session has expired, clear any session values
      elseif (empty($_SESSION['listkeys_bzid']) || empty($_SESSION['listkeys_session_created']) || $_SESSION['listkeys_session_created'] + (60 * $session_lifespan_minutes) < time()) {
        unset($_SESSION['listkeys_bzid'], $_SESSION['listkeys_username'], $_SESSION['listkeys_session_created']);
        $_SESSION['listkeys_flash'] = 'Session expired';
      }

      // User is attempting to create a new key
      elseif ($action === 'create') {
        // Make sure the hostname field isn't empty
        if (empty($data['hostname'])) {
          $_SESSION['listkeys_flash'] = 'A hostname must be provided when creating a key';
        } else {
          $hosting_key = $hosting_key_helper->create($data['hostname'], $_SESSION['listkeys_bzid']);

          if ($hosting_key !== null) {
            $_SESSION['listkeys_flash'] = 'Successfully created key';
          }
        }
      }

      // The user is attempting to delete an existing key
      elseif ($action === 'delete') {
        // Delete a key matching the key id and user id
        if ($hosting_key_helper->delete((int)$data['id'], $_SESSION['listkeys_bzid'])) {
          $_SESSION['listkeys_flash'] = 'Successfully deleted key';
        }
      }

      // Complain about invalid actions
      else {
        $_SESSION['listkeys_flash'] = 'Invalid action';
      }

      // Redirect the user back
      return $response
        ->withHeader('Location', $this->app->getRouteCollector()->getRouteParser()->urlFor('listkeys'))
        ->withStatus(302);
    }
    // Otherwise, this is going to be the GET method
    else {
      // The user is requesting a logout, so clear the session and redirect them back to the login page
      if ($action === 'logout') {
        unset($_SESSION['listkeys_bzid'], $_SESSION['listkeys_username'], $_SESSION['listkeys_session_created']);
        $_SESSION['listkeys_flash'] = 'You have logged out';

        return $response
          ->withHeader('Location', $this->app->getRouteCollector()->getRouteParser()->urlFor('listkeys'))
          ->withStatus(302);
      }

      // If the session is expired or has otherwise expired, clear session info and show the login page
      elseif (empty($_SESSION['listkeys_bzid']) || empty($_SESSION['listkeys_session_created']) || $_SESSION['listkeys_session_created'] + (60 * $session_lifespan_minutes) < time()) {
        $template_variables = [];

        // Handle the flash message, if one exists
        if (isset($_SESSION['listkeys_flash'])) {
          $template_variables['flash'] = $_SESSION['listkeys_flash'];
          unset($_SESSION['listkeys_flash']);
        }
        // Otherwise, if the session expired, inform the user of such
        elseif (!empty($_SESSION['listkeys_bzid'])) {
          $template_variables['flash'] = 'Session expired';
        }

        // Clear session info
        unset($_SESSION['listkeys_bzid'], $_SESSION['listkeys_username'], $_SESSION['listkeys_session_created']);

        return $twig->render($response, 'listkeys/login.html.twig', $template_variables);
      }

      // Otherwise, show the key management page
      else {
        // Fetch a list of existing keys for this user
        $keys = $hosting_key_helper->get_many_by_user($_SESSION['listkeys_bzid']);

        $template_variables = [
          'bzid' => $_SESSION['listkeys_bzid'],
          'username' => $_SESSION['listkeys_username'],
          'keys' => $keys
        ];

        // Handle the flash message, if one exists
        if (isset($_SESSION['listkeys_flash'])) {
          $template_variables['flash'] = $_SESSION['listkeys_flash'];
          unset($_SESSION['listkeys_flash']);
        }

        return $twig->render($response, 'listkeys/keys.html.twig', $template_variables);
      }
    }
  }
}
