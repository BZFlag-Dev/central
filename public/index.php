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

require __DIR__ . '/../vendor/autoload.php';
$app = (require __DIR__.'/../src/Bootstrap/container.php')();
$config = $app->getContainer()->get(Configuration::class);
(require __DIR__.'/../src/Bootstrap/middleware.php')($app, $config);
(require __DIR__.'/../src/Bootstrap/routes.php')($app, $config);
$app->run();
