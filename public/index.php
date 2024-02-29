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

use App\Controller\DocumentationController;
use App\Controller\GameServersController;
use App\Controller\LegacyListController;
use App\Util\PHPBBIntegration;
use DI\Bridge\Slim\Bridge;
use League\Config\Configuration;
use Nette\Schema\Expect;

require __DIR__ . '/../vendor/autoload.php';

$container = new \DI\Container();

$container->set(Configuration::class, function (): Configuration {
  // Define configuration schema
  $config = new Configuration([
    'debug' => Expect::bool(false),
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
    ])
  ]);

  // Merge our configuration file information
  $config->merge(require dirname(__DIR__).'/config.php');

  return $config;
});

$container->set(PDO::class, function (Configuration $config): PDO {
  $c = $config->get('database');
  return new PDO("mysql:dbname={$c['database']};host={$c['host']}", $c['username'], $c['password'], [
    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
    \PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8mb4'"
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

$container->set('what', function (Configuration $config, PDO $pdo, Redis $redis): PHPBBIntegration {
  return new PHPBBIntegration($config, $pdo, $redis);
});

// Create our application
$app = Bridge::create($container);

// Grab a pointer to the configuration
$config = $app->getContainer()->get(Configuration::class);

// Set up error handling
// TODO: Logging errors to a file
$errorMiddleware = $app->addErrorMiddleware($config->get('debug'), true, true);

// TODO: Delete expired authentication tokens and stale servers

// Second generation server list compatability
if ($_SERVER['SERVER_NAME'] === $config->get('legacy_host')) {
  $app->map(['GET', 'POST'], '/db/', [LegacyListController::class, 'db']);
  $app->map(['GET', 'POST'], '/bzfls.php', [LegacyListController::class, 'db']);
  // TODO: Legacy weblogin
}
// Third generation server list which is a modern REST API
else {
  // Write out usage information. Swagger docs?
  $app->get('/', [DocumentationController::class, 'usage'])->setName('usage');

  //
  // Game Servers
  //

  // Get servers
  $app->get('/servers', [GameServersController::class, 'get_all']);
  // Publish a new server or update an existing server
  $app->put('/servers', [GameServersController::class, 'create_or_update']);
  // Get information about a specific servers
  $app->get('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersController::class, 'get_one']);
  // Delete the specified server from the list
  $app->delete('/servers/{hostname}/{port:[1-9][0-9]*}', [GameServersController::class, 'delete_one']);

  //
  // Game Tokens
  //

  // User requests a token

  // Server consumes a token



}

$app->run();
