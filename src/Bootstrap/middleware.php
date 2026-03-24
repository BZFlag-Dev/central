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

use League\Config\Configuration;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Exception\HttpMethodNotAllowedException;
use Slim\Exception\HttpNotFoundException;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;

return function (App $app, Configuration $config) {
  // Add middleware
  $app->add(TwigMiddleware::createFromContainer($app, Twig::class));

  // Set up error handling
  $log_config = $config->get('logging');
  if ($log_config['log_other_errors']) {
    $error_logger = new Logger('error');
    $error_stream = new StreamHandler("{$log_config['log_directory']}/error.log", 400);
    $error_stream->setFormatter(new \Monolog\Formatter\LineFormatter("[%datetime%] %level_name%: %message% %context% %extra%\n"));
    $error_logger->pushHandler($error_stream);
    $error_logger->pushProcessor(new \Monolog\Processor\WebProcessor());
    $error_logger->pushProcessor(new \Monolog\Processor\IntrospectionProcessor());
  }

  $error_middleware = $app->addErrorMiddleware($config->get('debug'), true, true, $error_logger ?? null);

  $error_middleware->setErrorHandler(HttpNotFoundException::class, function (Request $request, Throwable $exception, bool $displayErrorDetails) use ($app) {
    $response = new Response();
    $twig = $app->getContainer()->get(Twig::class);
    return $twig->render($response, 'http_error.html.twig', [
      'code' => 404,
      'short_description' => 'Page Not Found',
      'message' => 'The requested URL was not found.'
    ])->withStatus(404);
  });

  $error_middleware->setErrorHandler(HttpMethodNotAllowedException::class, function (Request $request, Throwable $exception, bool $displayErrorDetails) use ($app) {
    $response = new Response();
    $twig = $app->getContainer()->get(Twig::class);
    return $twig->render($response, 'http_error.html.twig', [
      'code' => 405,
      'short_description' => 'Method Not Allowed',
      'message' => 'The requested method was not allowed for this URL.'
    ])->withStatus(405);
  });
};
