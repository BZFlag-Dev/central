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

use App\DatabaseHelper\GameServerHelper;
use App\DatabaseHelper\SessionHelper;
use App\DatabaseHelper\TokenHelper;

require __DIR__ . '/vendor/autoload.php';

// Build our container
$builder = new DI\ContainerBuilder();
$builder->addDefinitions(__DIR__.'/src/di-config.php');
$container = $builder->build();

// Delete expired sessions
$session_helper = $container->get(SessionHelper::class);
$session_helper->delete_expired();

// Delete stale tokens
$token_helper = $container->get(TokenHelper::class);
$token_helper->delete_stale();

// Delete stale servers
$gameserver_helper = $container->get(GameserverHelper::class);
$gameserver_helper->delete_stale();
