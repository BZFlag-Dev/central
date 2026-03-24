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

use App\Controller\LegacyListController;
use App\Controller\v1\GameServersController as GameServersControllerV1;
use App\Controller\v1\SessionsController as SessionsControllerV1;
use App\Middleware\FailHTTP;
use League\Config\Configuration;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Csrf\Guard;
use Slim\Routing\RouteCollectorProxy;

return function (App $app, Configuration $config) {
  // Second generation list server compatability
  if ($_SERVER['SERVER_NAME'] === $config->get('legacy_host')) {
    $app->get('/', function (Response $response): Response {
      return $response
        ->withHeader('Location', 'https://www.bzflag.org/')
        ->withStatus(302);
    });
    $app->map(['GET', 'POST'], '/db/', [LegacyListController::class, 'db'])->setName('legacy_bzfls');
    $app->map(['GET', 'POST'], '/bzfls.php', [LegacyListController::class, 'db']);
    $app->map(['GET', 'POST'], '/weblogin.php', [LegacyListController::class, 'weblogin'])
      ->setName('weblogin')->add(Guard::class);
    $app->map(['GET', 'POST'], '/listkeys/', [LegacyListController::class, 'listkeys'])
      ->setName('listkeys')->add(Guard::class);
  }
  // Third generation list server which is a modern REST API
  elseif ($config->get('enable_rest_api')) {
    $app->get('/', function (Request $request, Response $response): Response {
      return $response
        ->withHeader('Location', "https://{$request->getUri()->getHost()}/docs/")
        ->withStatus(302);
    });

    // v1 API development
    $app->group('/v1-dev', function (RouteCollectorProxy $group) {
      //
      // Game Servers
      //

      // Get servers
      $group->get('/servers', [GameServersControllerV1::class, 'get_many']);
      // Publish a new server or update an existing server
      $group->put('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersControllerV1::class, 'create_or_update']);
      // Delete the specified server from the list
      $group->delete('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersControllerV1::class, 'delete_one']);

      //
      // Sessions
      //

      // Create a session
      $group->post('/sessions', [SessionsControllerV1::class, 'create']);
      // Get information about a session
      $group->get('/sessions/{session_id}', [SessionsControllerV1::class, 'get_one']);
      // Delete a session
      $group->delete('/sessions/{session_id}', [SessionsControllerV1::class, 'delete_one']);
    })->add(FailHTTP::class);
  }
};
