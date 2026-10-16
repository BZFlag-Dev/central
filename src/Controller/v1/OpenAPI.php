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

use OpenApi\Spec as OAS;

#[OAS\OpenApi(
  info: new OAS\Info(
    version: '0.1-dev',
    description: 'A modern REST API that will be used by BZFlag servers and clients, as well as various websites and services. It provides an interface to the centralized services run by the BZFlag project, including the server list and authentication.',
    title: 'BZFlag Central Services API v1',
    termsOfService: 'https://www.bzflag.org/terms-of-use/'
  ),
  servers: [
    new OAS\Server(url: '/v1-dev'),
  ],
  tags: [
    new OAS\Tag(name: 'Servers', description: 'Operations that deal with game servers'),
    new OAS\Tag(name: 'Sessions', description: 'Operations that deal with authenticated player sessions'),
  ],
  externalDocs: new OAS\ExternalDocumentation(
    description: 'Find out more about BZFlag',
    url: 'https://www.bzflag.org/'
  ),
  components: new OAS\Components(
    schemas: [
      new OAS\Schema(
        schema: 'server',
        required: ['hostname', 'port', 'protocol', 'game_info', 'world_hash', 'description', 'build'],
        properties: [
          new OAS\Property(property: 'hostname', schema: new OAS\Schema(description: 'Public hostname of the server', type: 'string', readOnly: true, example: 'example.com')),
          new OAS\Property(property: 'port', schema: new OAS\Schema(description: 'Public port of the server', type: 'integer', default: 5154, maximum: 65535, minimum: 1, readOnly: true)),
          new OAS\Property(property: 'protocol', schema: new OAS\Schema(description: 'Server protocol version', type: 'string', readOnly: true, example: 'BZFS0221')),
          new OAS\Property(property: 'game_info', schema: new OAS\Schema(description: 'Hex encoded information about the game server status, such as player counts/limits', type: 'string', maxLength: 128, example: '0001007a00030000003200000000000032000000190019000000000018')),
          new OAS\Property(property: 'world_hash', schema: new OAS\Schema(description: 'Hash of the binary representation of the world, prefixed with the hash type', type: 'string', maxLength: 135, example: 'sha256:07123e1f482356c415f684407a3b8723e10b2cbbc0b8fcd6282c49d37c9c1abc')),
          new OAS\Property(property: 'description', schema: new OAS\Schema(description: 'Public description of the server', type: 'string', maxLength: 128, example: 'Public HiX server')),
          new OAS\Property(property: 'build', schema: new OAS\Schema(description: 'Build string of the server', type: 'string', maxLength: 255, example: '2.4.26.20230103-MAINT-linux-gnu-SDL2')),
          new OAS\Property(property: 'advert_groups', schema: new OAS\Schema(description: 'Array of group names to advertise to', type: 'array', items: new OAS\Schema\Items(type: 'string', maxLength: 128), writeOnly: true, example: ["ORG.GROUP1", "ORG.GROUP2"])),
        ]
      ),
      new OAS\Schema(
        schema: 'session',
        properties: [
          new OAS\Property(property: 'user_id', schema: new OAS\Schema(description: 'User ID number of the user the session belongs to', type: 'integer', example: 1006)),
          new OAS\Property(property: 'username', schema: new OAS\Schema(description: 'Name of the user', type: 'string', example: 'Son Goku')),
          new OAS\Property(property: 'session_expiration', schema: new OAS\Schema(description: 'UTC timestamp when the session will expire (though it may expire sooner if unused)', type: 'string', example: '2001-09-11 13:03:05')),
        ]
      ),
    ],
    responses: [
      new OAS\Response(response: 200, description: "Success"),
      new OAS\Response(response: 201, description: "Created"),
      new OAS\Response(response: 204, description: "No Content"),
      new OAS\Response(response: 400, description: "Bad Request"),
      new OAS\Response(response: 401, description: "Unauthorized"),
      new OAS\Response(response: 403, description: "Forbidden"),
      new OAS\Response(response: 404, description: "Not Found"),
      new OAS\Response(response: 429, description: "Too many requests"),
    ],
    requestBodies: [
      new OAS\RequestBody(
        request: 'server',
        content: [
          'application/json' => new OAS\MediaType\Json(ref: '#/components/schemas/server'),
        ]
      ),
    ],
    securitySchemes: [
      new OAS\Security\Scheme(
        securityScheme: 'server_key',
        type: 'apiKey',
        description: 'Server keys are created in the account management portal and associated with a specific hostname. They are used to host game servers under their associated hostname.',
        name: 'server-key',
        in: 'header'
      ),
      new OAS\Security\Scheme(
        securityScheme: 'user_session',
        type: 'apiKey',
        description: 'User sessions are created with the ```POST /sessions``` endpoint and used to execute authenticated requests to the API',
        name: 'session-id',
        in: 'header'
      ),
    ]
  )
)]
class OpenAPI
{
}
