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
use App\DatabaseHelper\SessionHelper;
use App\Util\PHPBBIntegration;
use Monolog\Logger;
use OpenApi\Attributes as OA;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

readonly class SessionsController
{
  public function __construct(private Logger $logger)
  {
  }

  #[OA\Post(
    path: '/sessions',
    description: 'Create an authenticated session',
    requestBody: new OA\RequestBody(
      content: [
        new OA\MediaType(
          mediaType: 'application/x-www-form-urlencoded',
          schema: new OA\Schema(
            required: [
              'username', 'password'
            ],
            properties: [
              new OA\Property(property: 'username', description: 'Registered user username', type: 'string'),
              new OA\Property(property: 'password', description: 'Registered user password', type: 'string')
            ]
          )
        )
      ]
    ),
    tags: ['Sessions'],
    responses: [
      new OA\Response(response: 200, description: 'Success', content: [
        'application/json' => new OA\JsonContent(
          allOf: [
            new OA\Schema(properties: [new OA\Property(property: 'session_id', description: 'The hexadecimal session ID', type: 'string', example: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')]),
            new OA\Schema(ref: '#/components/schemas/session')
          ]
        )
      ]),
      new OA\Response(response: 400, description: 'Bad request', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'bad_request',
          'errors' => ['Body must be application/x-www-form-urlencoded.']
        ])
      ]),
      new OA\Response(response: 401, description: 'Authentication Failure', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'unauthorized',
          'errors' => ['Username or password is incorrect']
        ])
      ]),
      new OA\Response(response: 429, description: 'Rate Limit Exceeded', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'rate_limit_exceeded',
          'errors' => ['Too many failed login attempts. Temporarily locked out.']
        ])
      ])
    ]
  )]
  public function create(Request $request, Response $response, SessionHelper $session_helper, PHPBBIntegration $phpbb): Response
  {
    // Verify the body content type is a typical form
    if ($request->getHeaderLine('Content-Type') !== 'application/x-www-form-urlencoded') {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::BadRequest, ['Body must be application/x-www-form-urlencoded.']));
      return $response->withStatus(400);
    }

    // Grab the POST data fields
    $data = $request->getParsedBody();

    // Username and password are required
    if (!isset($data['username']) || strlen($data['username']) === 0 || !isset($data['password']) || strlen($data['password']) === 0) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::Unauthorized, ['Username and password are required']));
      return $response
        ->withStatus(401)
        ->withHeader('Content-Type', 'application/json');
    }

    // Attempt to authenticate the player using the provided callsign and password
    $authentication_attempt = $phpbb->authenticate_player($data['username'], $data['password']);

    // If there was an authentication error, just bail out here
    if (isset($authentication_attempt['error'])) {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::Unauthorized, [$authentication_attempt['error']]));
      // TODO: Figure out a way to detect rate limiting failures and throw a 429 instead of a 401
      return $response
        ->withStatus(401)
        ->withHeader('Content-Type', 'application/json');
    }

    // Generate the session
    $session = $session_helper->create($authentication_attempt['bzid'], $authentication_attempt['callsign']);

    // If the session was created, then send it back to the client
    if ($session) {
      $response->getBody()->write(json_encode($session));
      return $response
        ->withHeader('Content-Type', 'application/json');
    }
    // Otherwise send an error back
    else {
      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::InternalServerError, ['errors' => ['Failed to generate session']]));
      return $response
        ->withStatus(500)
        ->withHeader('Content-Type', 'application/json');
    }
  }

  #[OA\Get(
    path: '/sessions/{session_id}',
    description: 'Get information about an authenticated session',
    tags: ['Sessions'],
    parameters: [
      new OA\PathParameter(name: 'session_id', description: 'Session ID of an authenticated session', required: true, schema: new OA\Schema(type: 'string'))
    ],
    responses: [
      new OA\Response(response: 200, description: 'Success', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/session')
      ]),
      new OA\Response(response: 404, description: 'Not Found', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'not_found',
          'errors' => ['Invalid session ID']
        ])
      ]),
      new OA\Response(response: 429, description: 'Rate Limit Exceeded', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'rate_limit_exceeded',
          'errors' => ['Too many failed session lookups. Temporarily locked out.']
        ])
      ])
    ]
  )]
  public function get_one(Request $request, Response $response, SessionHelper $session_helper, string $session_id): Response
  {
    // Look up session
    $session = $session_helper->get_one($session_id);

    // If we found a valid session, send it to the client
    if ($session) {
      $response->getBody()->write(json_encode($session));
      return $response
        ->withHeader('Content-Type', 'application/json');
    }
    // Otherwise, send an error
    else {
      // TODO: Rate limiting to prevent brute force attacks on session IDs

      // Log this failed attempt
      $this->logger->info('Attempted to fetch a session that did not exist.', [
        'session_id' => $session_id
      ]);

      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::NotFound, ['errors' => ['Invalid session ID']]));
      return $response
        ->withStatus(404);
    }
  }

  #[OA\Delete(
    path: '/sessions/{session_id}',
    description: 'Delete an authenticated session, effectively logging out a user session.',
    tags: ['Sessions'],
    parameters: [
      new OA\PathParameter(name: 'session_id', description: 'Session ID of an authenticated session', required: true, schema: new OA\Schema(type: 'string'))
    ],
    responses: [
      new OA\Response(ref: '#/components/responses/204', response: 204),
      new OA\Response(response: 404, description: 'Not Found', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'not_found',
          'errors' => ['Invalid session ID']
        ])
      ]),
      new OA\Response(response: 429, description: 'Rate Limit Exceeded', content: [
        'application/json' => new OA\JsonContent(ref: '#/components/schemas/error', example: [
          'type' => 'rate_limit_exceeded',
          'errors' => ['Too many failed session deletions. Temporarily locked out.']
        ])
      ])
    ]
  )]
  public function delete_one(Request $request, Response $response, SessionHelper $session_helper, string $session_id): Response
  {
    // Try to delete the session. If it was deleted, return an empty response
    if ($session_helper->delete($session_id)) {
      return $response->withStatus(204);
    }
    // Otherwise, if there was an issue deleting it (which would usually be that it didn't exist), return a 404
    else {
      // TODO: Rate limiting to prevent brute force attacks on session IDs

      // Log this failed attempt
      $this->logger->info('Attempted to delete a session that did not exist.', [
        'session_id' => $session_id
      ]);

      $response->getBody()->write(ErrorSchema::getJSON(ErrorType::NotFound, ['errors' => ['Invalid session ID']]));
      return $response
        ->withStatus(404);
    }
  }
}
