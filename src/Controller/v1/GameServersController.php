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

namespace App\Controller\v1;

use App\Controller\v1\Schema\ErrorSchema;
use App\Controller\v1\Schema\ErrorType;
use App\DatabaseHelper\GameServerHelper;
use App\DatabaseHelper\SessionHelper;
use App\Misc\BZFlagServer;
use App\Util\PHPBBIntegration;
use App\Util\Valid;
use Exception;
use Monolog\Logger;
use OpenApi\Attributes as OA;
use PDO;
use PDOException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

readonly class GameServersController
{
  public function __construct(private PDO $pdo, private Logger $logger)
  {

  }

  #[OA\Get(
    path: '/servers',
    description: 'Gets public servers and, if a valid user session is provided, any privately advertised servers that the user has access to.',
    security: [['user_session' => []]],
    tags: ['Servers'],
    parameters: [
      new OA\QueryParameter(
        name: 'protocol',
        description: 'Restrict results to servers running a specific protocol version.',
        schema: new OA\Schema(type: 'string'),
        example: 'BZFS0221'
      ),
      new OA\QueryParameter(
        name: 'hostname',
        description: 'Restrict the returned servers to those from a specific hostname.',
        schema: new OA\Schema(type: 'string')
      )
    ],
    responses: [
      new OA\Response(response: 200, description: 'Success', content: [
        'application/json' => new OA\JsonContent(
          type: 'array',
          items: new OA\Items(ref: '#/components/schemas/server')
        )
      ])
    ]
  )]
  public function get_many(Request $request, Response $response, GameServerHelper $game_server_helper, SessionHelper $session_helper): Response
  {
    // Grab the query parameters
    $data = $request->getQueryParams();

    // Check if a valid session was provided
    $user_id = null;
    if ($request->hasHeader('Session-ID')) {
      $session = $session_helper->get_one($request->getHeader('session-id')[0]);
      if ($session) {
        $user_id = $session['user_id'];
      }
    }

    // Fetch the servers
    $servers = $game_server_helper->get_many(
      protocol: $data['protocol'],
      hostname: $data['hostname'],
      user_id: $user_id,
    );

    if ($servers !== null) {
      $response->getBody()->write(json_encode($servers));
      return $response
        ->withHeader('Content-Type', 'application/json');
    }

    $response->getBody()->write(ErrorSchema::getJSON(ErrorType::InternalServerError, ['Error fetching servers']));
    return $response->withStatus(500);
  }

  #[OA\Put(
    path: '/servers/{hostname}/{port}',
    description: 'Create or update one server.',
    security: [['server_key' => []]],
    requestBody: new OA\RequestBody(ref: '#/components/requestBodies/server'),
    tags: ['Servers'],
    parameters: [
      new OA\PathParameter(name: 'hostname', description: 'Public hostname of the server', required: true, schema: new OA\Schema(type: 'string')),
      new OA\PathParameter(name: 'port', description: 'Public port of the server', required: true, schema: new OA\Schema(type: 'integer'))
    ],
    responses: [
      new OA\Response(response: 200, description: 'Updated'),
      new OA\Response(response: 201, description: 'Created'),
      new OA\Response(response: 400, description: 'Bad Request', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'bad_request',
          'errors' => [
            'Invalid hostname in public address.',
            'Invalid server description.'
          ]
        ])
      ]),
      new OA\Response(response: 401, description: 'Authentication Failure', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'unauthorized',
          'errors' => ['Host mismatch for server key.']
        ])
      ]),
    ]
  )]
  public function create_or_update(Request $request, Response $response, PHPBBIntegration $phpbb, string $hostname, int $port): Response
  {
    // Verify the body content type is JSON
    if ($request->getHeaderLine('Content-Type') !== 'application/json') {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::BadRequest, ['Body must be application/json.']));
      return $response->withStatus(400);
    }

    // Verify a server key was provided, which will be validated later
    if (!$request->hasHeader('Server-Key')) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::Unauthorized, ['Missing server authentication key.']));
      return $response
        ->withStatus(401)
        ->withHeader('Content-Type', 'application/json');
    }

    // Attempt to parse the body
    $data = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::BadRequest, ['Failed to parse JSON body.']));
      return $response
        ->withStatus(400)
        ->withHeader('Content-Type', 'application/json');
    }

    // Track any errors
    $errors = [];

    // Validate the provided values
    if (!Valid::serverHostname($hostname)) {
      $errors[] = 'Invalid hostname in public address.';
    }
    if (!Valid::serverPort($port)) {
      $errors[] = 'Invalid port in public address.';
    }

    // Protocol version
    if (empty($data['protocol']) || !Valid::serverProtocol($data['protocol'])) {
      $errors[] = 'Missing or invalid protocol version.';
    }

    // Game information
    if (empty($data['game_info']) || !Valid::serverGameInfo($data['game_info'])) {
      $errors[] = 'Missing or invalid game info.';
    }

    // World hash
    // TODO: More validation than just length
    if (empty($data['world_hash']) || strlen($data['world_hash']) > 135) {
      $errors[] = 'Missing or invalid world hash.';
    }

    // Server description (optional, so only check if not empty)
    if (empty($data['description'])) {
      $data['description'] = '';
    } elseif (!Valid::serverDescription($data['description'])) {
      $errors[] = 'Invalid server description.';
    }

    // Basic check of advert groups, if provided
    if (!empty($data['advert_groups']) && !is_array($data['advert_groups'])) {
      $errors[] = 'Advert groups should be an array.';
    }

    // Verify the server key
    $server_key = $request->getHeader('Server-Key')[0];
    try {
      $statement = $this->pdo->prepare('SELECT id, host, user_id FROM hosting_keys WHERE key_string = :key_string');
      $statement->bindValue('key_string', $server_key);
      $statement->execute();
      $hosting_key = $statement->fetch();

      // Verify that we found a matching key
      if (!$hosting_key) {
        $this->logger->debug('Server key not found.', [
          'hostname' => $hostname,
          'port' => $port,
          'server_key' => $server_key
        ]);
        $server_key_error = 'Invalid server authentication key.';
      } else {
        // The host on the key must exactly match the public address
        if (strcasecmp($hosting_key['host'], $hostname) !== 0) {
          $this->logger->error('Server key host mismatch', [
            'hostname' => $hostname,
            'key_hostname' => $hosting_key['host'],
            'port' => $port,
            'server_key' => $server_key
          ]);
          $server_key_error = 'Host mismatch for server key.';
        } else {
          // Attempt to get the server owner name
          $server_owner = $phpbb->get_username_by_user_id($hosting_key['user_id']);

          // If the owner lookup failed, error
          if (!$server_owner) {
            $this->logger->error('Server key owner lookup failed', [
              'hostname' => $hostname,
              'port' => $port,
              'server_key' => $server_key,
              'user_id' => $hosting_key['user_id']
            ]);
            $server_key_error = 'Invalid server key.';
          }
        }
      }
    } catch (PDOException $e) {
      $this->logger->critical('Database error when fetching server key', [
        'server_key' => $server_key,
        'error' => $e->getMessage()
      ]);
      $server_key_error = 'Invalid server key.';
    }

    // If there was an error when lookup up the key or the key owner, bail out here
    if (isset($server_key_error)) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::Unauthorized, [$server_key_error]));
      return $response->withStatus(401);
    }

    // TODO: Verify that the IP of this HTTP requests is contained in the DNS response of the hostname

    // Verify that we can connect to the server
    try {
      new BZFlagServer($hostname, $port, $data['protocol']);
    } catch (Exception $e) {
      $this->logger->error($e->getMessage(), [
        'hostname' => $hostname,
        'port' => $port,
        'protocol' => $data['protocol']
      ]);
      $errors[] = 'Failed to connect to or verify running server.';
    }

    // If we have no errors up to this point, try to add/update the server
    if (empty($errors)) {
      try {
        // Check if the server already exists
        $sta = $this->pdo->prepare('SELECT id, protocol, hosting_key_id FROM servers WHERE host = :hostname AND port = :port LIMIT 1');
        $sta->bindValue('hostname', $hostname);
        $sta->bindValue('port', $port, PDO::PARAM_INT);
        $sta->execute();
        $existing = $sta->fetch();

        // If this server already exists, update it
        if ($existing) {
          // If the hosting key doesn't match, return a 401
          if ($existing['hosting_key_id'] !== $hosting_key['id']) {
            $response->getBody()->write(ErrorSchema::getJSON(ErrorType::Unauthorized, ['Hosting key mismatch when updating server.']));
            return $response->withStatus(401);
          } elseif ($existing['protocol'] !== $data['protocol']) {
            $errors[] = 'Protocol version mismatch when updating server.';
          } else {
            $sta = $this->pdo->prepare("UPDATE servers SET game_info = :game_info, world_hash = :world_hash, description = :description, owner = :owner, when_updated = NOW() WHERE id = :id");
            $sta->bindValue('id', $existing['id'], PDO::PARAM_INT);
            $sta->bindValue('game_info', $data['game_info']);
            $sta->bindValue('world_hash', $data['world_hash']);
            $sta->bindValue('description', $data['description']);
            $sta->bindValue('owner', $server_owner);
            $sta->execute();
          }
        } // Otherwise, insert a new server entry
        else {
          $sta = $this->pdo->prepare("INSERT INTO servers (host, port, hosting_key_id, protocol, game_info, world_hash, description, owner) VALUES (:hostname, :port, :hosting_key_id, :protocol, :game_info, :world_hash, :description, :owner)");
          $sta->bindValue('hostname', $hostname);
          $sta->bindValue('port', $port, PDO::PARAM_INT);
          $sta->bindValue('hosting_key_id', $hosting_key['id'], PDO::PARAM_INT);
          $sta->bindValue('protocol', $data['protocol']);
          $sta->bindValue('game_info', $data['game_info']);
          $sta->bindValue('world_hash', $data['world_hash']);
          $sta->bindValue('description', $data['description']);
          $sta->bindValue('owner', $server_owner);

          // If the server was created, and the advert groups is non-empty and does not contain the EVERYONE group,
          // then store the advert groups.
          if ($sta->execute() && !empty($data['advert_groups']) && !in_array('EVERYONE', $data['advert_groups'], true)) {
            $server_id = $this->pdo->lastInsertId();
            $sta = $this->pdo->prepare('INSERT INTO server_advert_groups (server_id, group_id) VALUES (:server_id, :group_id)');
            $sta->bindValue('server_id', $server_id, PDO::PARAM_INT);
            foreach($data['advert_groups'] as $advert_group) {
              $group_id = $phpbb->get_group_id_by_name($advert_group);
              if ($group_id) {
                $sta->bindValue('group_id', $group_id);
                $sta->execute();
              }
            }
          }
        }
      } catch(PDOException $e) {
        $this->logger->error('Database error when adding or updating server.', [
          'hostname' => $hostname,
          'port' => $port,
          'error' => $e->getMessage()
        ]);
        $errors[] = 'Failed to add or update the server.';
      }
    }

    // If we had any errors, report them
    if (!empty($errors)) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::BadRequest, $errors));
      return $response
        ->withStatus(400)
        ->withHeader('Content-Type', 'application/json');
    }
    // Otherwise, return an appropriate HTTP code and include the server owner name
    else {
      $response->getBody()->write(json_encode([
        'owner' => $server_owner
      ]));
      return $response
        ->withStatus(($existing) ? 200 : 201)
        ->withHeader('Content-Type', 'application/json');
    }
  }

  #[OA\Delete(
    path: '/servers/{hostname}/{port}',
    description: 'Remove one server from the server list.',
    security: [['server_key' => []]],
    tags: ['Servers'],
    parameters: [
      new OA\PathParameter(name: 'hostname', description: 'Public hostname of the server', required: true, schema: new OA\Schema(type: 'string')),
      new OA\PathParameter(name: 'port', description: 'Public port of the server', required: true, schema: new OA\Schema(type: 'integer'))
    ],
    responses: [
      new OA\Response(response: 204, description: 'Deleted'),
      new OA\Response(response: 400, description: 'Bad Request', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'bad_request',
          'errors' => [
            'Missing server key.',
          ]
        ])
      ]),
      new OA\Response(response: 404, description: 'Not Found', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'not_found',
          'errors' => [
            'Server not found.',
          ]
        ])
      ])
    ]
  )]
  public function delete_one(Request $request, Response $response, GameServerHelper $game_server_helper, string $hostname, int $port): Response
  {
    // Track any errors
    $errors = [];

    // Verify a valid server key was provided
    if (!$request->hasHeader('Server-Key')) {
      $errors[] = 'Missing server key.';
    }

    // Validate the provided values
    if (!Valid::serverHostname($hostname)) {
      $errors[] = 'Invalid hostname in public address.';
    }
    if (!Valid::serverPort($port)) {
      $errors[] = 'Invalid port in public address.';
    }

    // If there were no errors in the provided data, try to look up and then delete the server
    if (empty($errors)) {
      // Fetch information about this server
      $server = $game_server_helper->get_id_and_key_from_hostname_and_port($hostname, $port);
      $server_key = $request->getHeader('Server-Key')[0];

      // If we found the server and the key matches, delete it
      if ($server !== null && $server['server_key'] === $server_key && $game_server_helper->delete($server['id'])) {
        return $response->withStatus(204);
      }

      // Didn't find a server that also used the provided key, so return a 404
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::NotFound, ['Server not found.']));
      return $response->withStatus(404);
    }
    // Otherwise, show the errors
    else {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::BadRequest, $errors));
      return $response
        ->withStatus(400)
        ->withHeader('Content-Type', 'application/json');
    }
  }
}
