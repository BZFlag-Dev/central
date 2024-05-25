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
use App\Controller\v1\GameServersController;
use App\Controller\v1\SessionsController;
use DI\Bridge\Slim\Bridge;
use League\Config\Configuration;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Nette\Schema\Expect;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\App;
use Slim\Csrf\Guard;
use Slim\Routing\RouteCollectorProxy;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;

require __DIR__ . '/../vendor/autoload.php';

$container = new \DI\Container();

$container->set(Configuration::class, function (): Configuration {
  // Define configuration schema
  $config = new Configuration([
    // Hostname that, when used, triggers the legacy bzfls2 compatible interface
    'legacy_host' => Expect::string()->required(),
    // If a server has not been updated recently, it will be purged. Value in seconds.
    'server_stale_time' => Expect::int(1830),
    // Player authentication tokens are valid for a limited number of seconds
    'token_lifetime' => Expect::int(300),
    'login' => Expect::structure([
      'max_failed_attempts' => Expect::int(5),
      'attempt_duration' => Expect::int(300),
      'lockout_duration' => Expect::int(1800)
    ]),
    'session' => Expect::structure([
      // Maximum session lifespan in hours (defaults to 90 days)
      'max_lifespan' => Expect::int(2160),
      // Maximum idle session time in hours (defaults to 16 days)
      'max_idle' => Expect::int(384)
    ]),
    'phpbb' => Expect::structure([
      'root_path' => Expect::string()->required(),
      'database' => Expect::string()->required(),
      'prefix' => Expect::string('phpbb_')
    ]),
    'redis' => Expect::structure([
      'host' => Expect::string('127.0.0.1'),
      'password' => Expect::string()
    ]),
    'database' => Expect::structure([
      'host' => Expect::string('127.0.0.1'),
      'database' => Expect::string()->required(),
      'username' => Expect::string()->required(),
      'password' => Expect::string()->required()
    ]),
    // Display debug messages in the browser? Disable for production site
    'debug' => Expect::bool(false),
    // Activity/error logging
    'logging' => Expect::structure([
      // Absolute path to the log directory
      'log_directory' => Expect::string(dirname(__DIR__).'/var/log'),
      // Application error level, which controls the level of detail written to app.log
      // Debug = 100, Info = 200, Notice = 250, Warning = 300, Error = 400, Critical = 500, Alert = 550, Emergency = 600
      'app_level' => Expect::int(200)->min(100)->max(600),
      // Log other errors (such as 404 errors or other fatal PHP errors) to error.log
      'log_other_errors' => Expect::bool(false)
    ])
  ]);

  // Merge our configuration file information
  $config->merge(require dirname(__DIR__).'/config.php');

  return $config;
});

$container->set(Twig::class, function () {
  return Twig::create(dirname(__DIR__).'/views', [
    'cache' => dirname(__DIR__).'/var/cache/twig',
    'auto_reload' => true
  ]);
});

$container->set(PDO::class, function (Configuration $config): PDO {
  $c = $config->get('database');
  return new PDO("mysql:dbname={$c['database']};host={$c['host']}", $c['username'], $c['password'], [
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"
  ]);
});

$container->set(Redis::class, function (Configuration $config): Redis {
  $c = $config->get('redis');
  $redis = new Redis();
  $redis->connect($c['host']);
  if (!empty($c['password'])) {
    $redis->auth($c['password']);
  }
  return $redis;
});

$container->set(Logger::class, function (Configuration $config): Logger {
  $c = $config->get('logging');
  $logger = new Logger('bzfls');
  $stream = new StreamHandler("{$c['log_directory']}/app.log", $c['app_level']);
  $stream->setFormatter(new \Monolog\Formatter\LineFormatter("[%datetime%] %level_name%: %message% %context% %extra%\n"));
  $logger->pushHandler($stream);
  return $logger;
});

$container->set(Guard::class, function (App $app, Twig $twig): Guard {
  // Start a session if it hasn't been already
  if (session_status() === PHP_SESSION_NONE) {
    // TODO: Support options being passed?
    session_start();
  }

  // Create and configure the CSRF guard
  $csrf = new Guard($app->getResponseFactory(), failureHandler: function (Request $request, RequestHandlerInterface $handler) {
    $request = $request->withAttribute('csrf_status', false);
    return $handler->handle($request);
  }, persistentTokenMode: true);

  // Add Twig extension for the CSRF token
  $twig->getEnvironment()->addExtension(new \App\Misc\CsrfExtension($csrf));

  return $csrf;
});

// Create our application
$app = Bridge::create($container);

// Add middleware
$app->add(TwigMiddleware::createFromContainer($app, Twig::class));

// Grab a pointer to the configuration
$config = $app->getContainer()->get(Configuration::class);

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

$app->addErrorMiddleware($config->get('debug'), true, true, $error_logger ?? null);

// Second generation server list compatability
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
// Third generation server list which is a modern REST API
else {
  $app->get('/', function (Response $response): Response {
    return $response
      ->withHeader('Location', '/docs/')
      ->withStatus(302);
  });

  // v1 API development
  $app->group('/v1-dev', function (RouteCollectorProxy $group) {
    //
    // Game Servers
    //

    // Get servers
    $group->get('/servers', [GameServersController::class, 'get_many']);
    // Publish a new server or update an existing server
    $group->put('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersController::class, 'create_or_update']);
    // Delete the specified server from the list
    $group->delete('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersController::class, 'delete_one']);

    //
    // Sessions
    //

    // Create a session
    $group->post('/sessions', [SessionsController::class, 'create']);
    // Get information about a session
    $group->get('/sessions/{session_id}', [SessionsController::class, 'get_one']);
    // Delete a session
    $group->delete('/sessions/{session_id}', [SessionsController::class, 'delete_one']);
  });
}

$app->run();
