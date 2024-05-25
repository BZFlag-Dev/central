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

use OpenApi\Attributes as OA;

#[OA\OpenApi(
  info: new OA\Info(
    version: '0.1-dev',
    description: 'A modern REST API that will be used by BZFlag servers and clients, as well as various websites and services. It provides an interface to the centralized services run by the BZFlag project, including the server list and authentication.',
    title: 'BZFlag Central Services API v1',
    termsOfService: 'https://www.bzflag.org/terms-of-use/'
  ),
  servers: [
    new OA\Server(url: 'https://central.bzflag.porteighty.org/v1-dev')
  ],
  tags: [
    new OA\Tag('Servers', description: 'Operations that deal with game servers'),
    new OA\Tag('Sessions', description: 'Operations that deal with authenticated player sessions'),
  ],
  externalDocs: new OA\ExternalDocumentation(
    description: 'Find out more about BZFlag',
    url: 'https://www.bzflag.org/'
  ),
  components: new OA\Components(
    schemas: [
      new OA\Schema(
        schema: 'server',
        required: ['protocol', 'hostname', 'port', 'game_info'],
        properties: [
          new OA\Property(property: 'hostname', description: 'Public hostname of the server', type: 'string', readOnly: true, example: 'example.com'),
          new OA\Property(property: 'port', description: 'Public port of the server', type: 'integer', default: 5154, maximum: 65535, minimum: 1, readOnly: true),
          new OA\Property(property: 'protocol', description: 'Server protocol version', type: 'string', example: 'BZFS0221'),
          new OA\Property(property: 'game_info', description: 'Hex encoded information about the game server status, such as player counts/limits', type: 'string', maxLength: 128, example: '0001007a00030000003200000000000032000000190019000000000018'),
          new OA\Property(property: 'world_hash', description: 'Hash of the binary representation of the world, prefixed with the hash type', type: 'string', maxLength: 135, example: 'sha256:07123e1f482356c415f684407a3b8723e10b2cbbc0b8fcd6282c49d37c9c1abc'),
          new OA\Property(property: 'description', description: 'Public description of the server', type: 'string', maxLength: 128, example: 'Public HiX server'),
          new OA\Property(property: 'advert_groups', description: 'Array of group names to advertise to', type: 'array', items: new OA\Items(type: 'string', maxLength: 128), writeOnly: true, example: ["ORG.GROUP1", "ORG.GROUP2"])
        ]
      ),
      new OA\Schema(
        schema: 'session',
        properties: [
          new OA\Property(property: 'user_id', description: 'User ID number of the user the session belongs to', type: 'integer', example: 1006),
          new OA\Property(property: 'username', description: 'Name of the user', type: 'string', example: 'Son Goku'),
          new OA\Property(property: 'session_expiration', description: 'UTC timestamp when the session will expire (though it may expire sooner if unused)', type: 'string', example: '2001-09-11 13:03:05')
        ]
      )
    ],
    responses: [
      new OA\Response(response: 200, description: "Success"),
      new OA\Response(response: 201, description: "Created"),
      new OA\Response(response: 204, description: "No Content"),
      new OA\Response(response: 400, description: "Bad Request"),
      new OA\Response(response: 401, description: "Unauthorized"),
      new OA\Response(response: 403, description: "Forbidden"),
      new OA\Response(response: 404, description: "Not Found"),
      new OA\Response(response: 429, description: "Too many requests")
    ],
    requestBodies: [
      new OA\RequestBody(
        request: 'server',
        content: [
          'application/json' => new OA\JsonContent(ref: '#/components/schemas/server')
        ]
      )
    ],
    securitySchemes: [
      new OA\SecurityScheme(
        securityScheme: 'server_key',
        type: 'apiKey',
        description: 'Server keys are created in the account management portal and associated with a specific hostname. They are used to host game servers under their associated hostname.',
        name: 'server-key',
        in: 'header'
      ),
      new OA\SecurityScheme(
        securityScheme: 'user_session',
        type: 'apiKey',
        description: 'User sessions are created with the ```POST /sessions``` endpoint and used to execute authenticated requests to the API',
        name: 'session-id',
        in: 'header'
      )
    ]
  )
)]
class OpenAPI
{
}
