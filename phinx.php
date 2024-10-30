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

use Nette\Schema\Expect;

require(__DIR__ . '/vendor/autoload.php');

$config = new League\Config\Configuration([
  'database' => Expect::structure([
    'host' => Expect::string('127.0.0.1'),
    'port' => Expect::int(3306),
    'database' => Expect::string()->required(),
    'username' => Expect::string()->required(),
    'password' => Expect::string()
  ])
]);
$config->merge(require(__DIR__ . '/phinx-config.php'));

return
  [
    'paths' => [
      'migrations' => '%%PHINX_CONFIG_DIR%%/db/migrations',
      'seeds' => '%%PHINX_CONFIG_DIR%%/db/seeds'
    ],
    'environments' => [
      'default_migration_table' => 'phinxlog',
      'default_environment' => 'production',
      'production' => [
        'adapter' => 'mysql',
        'host' => 'localhost',
        'name' => $config->get('database.database'),
        'user' => $config->get('database.username'),
        'pass' => $config->get('database.password'),
        'port' => $config->get('database.port'),
        'charset' => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
      ],
    ],
    'version_order' => 'creation'
  ];
