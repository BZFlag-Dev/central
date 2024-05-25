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

namespace App\Util;

class Valid
{
  public static function serverHostname(string $hostname): bool
  {
    return strlen($hostname) > 0 && strlen($hostname) <= 255 && preg_match('/^([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$/', $hostname) === 1;
  }

  // Must be a number between 1 and 65535 inclusive
  public static function serverPort(string|int $port): bool
  {
    if (is_string($port)) {
      if (!ctype_digit($port)) {
        return false;
      }
      $nport = (int)$port;
      return $nport >= 1 && $nport <= 65535;
    } else {
      return $port >= 1 && $port <= 65535;
    }
  }

  // Protocol is an 8 character string with 4 uppercase alpha and 4 numeric characters
  public static function serverProtocol(string $protocol): bool
  {
    return preg_match('/^[A-Z]{4}[0-9]{4}$/', $protocol) === 1;
  }

  // Must be a hexadecimal value with no whitespace
  public static function serverGameInfo(string $game_info): bool
  {
    return strlen($game_info) <= 255 && ctype_xdigit($game_info);
  }

  public static function serverDescription(string $description): bool
  {
    // TODO: Do we eventually want to allow UTF-8 descriptions?
    return strlen($description) <= 255 && ctype_print($description);
  }
}
