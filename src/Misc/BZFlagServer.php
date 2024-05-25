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

namespace App\Misc;

use Exception;

class BZFlagServer
{
  private $socket;

  private string|null $protocol = null;

  /**
   * @throws Exception
   */
  public function __construct(string $hostname_or_ip, int $port = 5154, string $expected_protocol = null)
  {
    $this->socket = fsockopen($hostname_or_ip, $port, $errno, $errstr, 5);
    if (!$this->socket) {
      throw new Exception("Unable to open socket to BZFlag server");
    }

    // For versions other than 1.10 and 2.0, tell the server that we want to use the BZFlag protocol
    if ($expected_protocol !== 'BZFS0026' && $expected_protocol !== 'BZFS1910') {
      $result = fwrite($this->socket, "BZFLAG\r\n\r\n");
      if ($result === false || $result != strlen("BZFLAG\r\n\r\n")) {
        throw new Exception("Unable to write magic string");
      }
    }

    // Set the socket non-blocking
    socket_set_blocking($this->socket, false);

    // Create a blank buffer
    $buffer = '';

    // Try to read the protocol string (and the player ID, which we don't need)
    $read_start = microtime(true);
    while (strlen($buffer) < 9) {
      // If we've exceeded our packet receive timeout, bail out
      if (microtime(true) > $read_start + 4) {
        throw new Exception("Timed out reading protocol version");
      }

      $chunk = fread($this->socket, 9 - strlen($buffer));
      if ($chunk === false) {
        throw new Exception("Received an error when reading from socket");
      } else {
        $buffer .= $chunk;
        usleep(15000);
      }
    }

    // Store the protocol
    $this->protocol = substr($buffer, 0, 8);

    // Verify the protocol matches the expected version
    if ($this->protocol !== $expected_protocol) {
      $this->protocol = null;
      throw new Exception("Actual protocol does not match the expected protocol");
    }
  }

  public function getProtocol(): string|null
  {
    return $this->protocol;
  }
}
