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
use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Random\RandomException;
use Slim\App;

class LegacyListController
{
  public function db(App $app, Request $request, Response $response, PDO $pdo): Response
  {
    // Grab the request data for this request
    $data = ($request->getMethod() === 'POST') ? $request->getParsedBody() : $request->getQueryParams();

    // Pick an action, any action, no not that one
    switch($data['action']??'') {
      case 'LIST':
        return $this->list($app, $request, $response, $pdo, $data);
      case 'GETTOKEN':
        return $this->get_token($app, $request, $response, $pdo, $data);
      case 'ADD':
        return $this->add_server($app, $request, $response, $pdo, $data);
      case 'REMOVE':
        return $this->remove_server($app, $request, $response, $pdo, $data);
      case 'CHECKTOKENS':
        return $this->check_tokens($app, $request, $response, $pdo, $data);
      default:
        return $this->usage($app, $request, $response);
    }
  }

  private function authenticate_player(App $app, PDO $pdo, array $data): string
  {
    // If either the callsign or password are empty, just bail out here
    if (empty($data['callsign']) || empty($data['password'])) {
      return '';
    }

    $phpbb = $app->getContainer()->get(PHPBBIntegration::class);

    $data = $phpbb->authenticate_player($data['callsign'], $data['password']);

    // If the authentication failed, throw a NOTOK back
    if (!empty($data['error'])) {
      return "NOTOK: {$data['error']}\n";
    }
    // Otherwise, let's generate, store, and return a token
    else {
      try {
        //$token = random_int(0, 2147483647);
        // TODO: Test if this works. This generates a 20 character string. The client/server allocate 22 bytes,
        //   including the terminating NUL, for the token.
        $token = bin2hex(random_bytes(10));
        $statement = $pdo->prepare('INSERT INTO auth_tokens (user_id, token, ipv4) VALUES (:user_id, :token, :ipv4)');
        $statement->bindParam('user_id', $data['bzid'], PDO::PARAM_INT);
        $statement->bindParam('token', $token);
        $statement->bindParam('ipv4', $_SERVER['REMOTE_ADDR']);
        $statement->execute();
        return "TOKEN: $token\n";
      } catch (RandomException|\PDOException $e) {
        // TODO: Log failure
        return "NOTOK: Failed to generate token...\n";
      }
    }
  }

  private function list(App $app, Request $request, Response $response, PDO $pdo, array $data): Response
  {
    $sql = 'SELECT id, host, port, protocol, game_info, description, has_advert_groups FROM servers';
    if (isset($data['version'])) {
      $sql .= ' WHERE protocol = :protocol';
    }
    $sta = $pdo->prepare($sql);
    if (isset($data['version'])) {
      $sta->bindValue('protocol', $data['version']);
    }
    $sta->execute();
    $body = $response->getBody();
    $body->write($this->authenticate_player($app, $pdo, $data));
    while($row = $sta->fetch()) {
      $body->write("{$row['host']}:{$row['port']} {$row['protocol']} {$row['game_info']} 127.0.0.1 {$row['description']}\n");
    }

    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function get_token(App $app, Request $request, Response $response, PDO $pdo, array $data): Response
  {
    $response->getBody()->write($this->authenticate_player($app, $pdo, $data));
    return $response
      ->withHeader('Content-Type', 'text/plain');
  }

  private function add_server(App $app, Request $request, Response $response, PDO $pdo, array $data): Response
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
    }
    else if (!Valid::serverDescription($data['title'])) {
      $errors[] = 'Missing or invalid server description.';
    }

    // Tokens to check

    // Groups to check

    // Server hosting key (not required for protocol versions 'BZFS0026' [2.0] or 'BZFS1910' [1.10])


    // Check if the provided server token allows manipulating this hostname

    // Check if there were any errors
    if (!empty($errors)) {
      $response->getBody()->write('ERROR: '.implode(' ', $errors));
      return $response
        ->withHeader('Content-Type', 'text/plain');
    }
    else {
      // Check if the server already exists
      $sta = $pdo->prepare("SELECT id FROM servers WHERE host = :host AND port = :port LIMIT 1");
      $sta->bindValue('host', $hostname);
      $sta->bindValue('port', $port, PDO::PARAM_INT);
      $sta->execute();

      // If this server already exists, update it
      // TODO: Only allow updating if the same hosting key is used?
      if ($sta->rowCount() === 1) {
        $existing = $sta->fetch(PDO::FETCH_ASSOC);

        $sta = $pdo->prepare("UPDATE servers SET protocol = :protocol, game_info = :game_info, description = :description, has_advert_groups = :has_advert_groups WHERE id = :id");
        $sta->bindValue('id', $existing['id'], PDO::PARAM_INT);
        $sta->bindValue('protocol', $data['version']);
        $sta->bindValue('game_info', $data['gameinfo']);
        $sta->bindValue('description', $data['title']);
        $sta->bindValue('has_advert_groups', 0);
        $sta->execute();
      }
      // Otherwise, insert a new server entry
      else {
        $sta = $pdo->prepare("INSERT INTO servers (host, port, protocol, game_info, description, has_advert_groups) VALUES (:host, :port, :protocol, :game_info, :description, :has_advert_groups)");
        $sta->bindValue('host', $hostname);
        $sta->bindValue('port', $port, PDO::PARAM_INT);
        $sta->bindValue('protocol', $data['version']);
        $sta->bindValue('game_info', $data['gameinfo']);
        $sta->bindValue('description', $data['title']);
        $sta->bindValue('has_advert_groups', 0);
        $sta->execute();
      }

      $response->getBody()->write("ADD: $hostname:$port");
      return $response
        ->withHeader('Content-Type', 'text/plain');
    }
  }

  private function remove_server(App $app, Request $request, Response $response, PDO $pdo, array $data): Response
  {

  }

  private function check_tokens(App $app, Request $request, Response $response, PDO $pdo, array $data): Response
  {

  }

  private function usage(App $app, Request $request, Response $response): Response
  {
    $response->getBody()->write('Put usage info here');
    return $response;
  }
}
