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

namespace App\DatabaseHelper;

use League\Config\Configuration;
use Monolog\Logger;
use PDO;
use PDOException;
use PDOStatement;
use Random\RandomException;

class TokenHelper
{
  private int $token_lifetime;
  public function __construct(private readonly PDO $pdo, Configuration $config, private readonly Logger $logger)
  {
    $this->token_lifetime = $config->get('token_lifetime');
  }

  public function create(int $bzid, ?string $player_ipv4 = null, ?string $server_host = null, ?int $server_port = null): string|null
  {
    try {
      // Generate a 20 character string for the authentication token. The client/server allocate 22 bytes, including
      // the terminating NUL, for the token.
      $token = bin2hex(random_bytes(10));


      $statement = $this->pdo->prepare('INSERT INTO auth_tokens (user_id, token, player_ipv4, server_host, server_port) VALUES (:user_id, :token, :player_ipv4, :server_host, :server_port)');
      $statement->bindValue('user_id', $bzid, PDO::PARAM_INT);
      $statement->bindValue('token', $token);
      $statement->bindValue('player_ipv4', $player_ipv4);
      $statement->bindValue('server_host', $server_host);
      $statement->bindValue('server_port', $server_port, PDO::PARAM_INT);
      $statement->execute();
      return $token;
    } catch (RandomException|PDOException $e) {
      $this->logger->error('Failed to generate authentication token', [
        'bzid' => $bzid,
        'error' => $e->getMessage(),
      ]);
      return null;
    }
  }

  public function validate(string $callsign, int $user_id, string $token_string, ?string $player_ipv4 = null, ?string $server_host = null, ?int $server_port = null): bool
  {
    // Delete a matching non-expired token, returning the values we need
    // NOTE: The cron job will take care of cleaning up expired tokens
    try {
      $statement = $this->pdo->prepare('DELETE FROM auth_tokens WHERE user_id = :user_id AND token = :token AND DATE_ADD(when_created, INTERVAL :token_lifetime SECOND) > NOW() RETURNING player_ipv4, server_host, server_port');
      $statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
      $statement->bindValue('token', $token_string);
      $statement->bindValue('token_lifetime', $this->token_lifetime, PDO::PARAM_INT);
      $statement->execute();
      $token = $statement->fetch();
    } catch (PDOException $e) {
      $this->logger->critical('Failed to prepare one or more statements for processing tokens.', ['error' => $e->getMessage()]);
      return false;
    }

    // Check if we found a token
    if (!$token) {
      $this->logger->error('Authentication token not found', ['user_id' => $user_id, 'token' => $token_string]);
      return false;
    }

    // If the server host/port was stored with this token, compare the requested host/port with the actual host/port
    if ($token['server_host'] !== null && $token['server_host'] !== '' && $server_host !== null && $token['server_host'] === $server_host && $token['server_port'] === $server_port) {
      $this->logger->info('Successfully consumed token using host/port match', [
        'callsign' => $callsign,
        'host' => $server_host,
        'port' => $server_port,
      ]);
      return true;
    }
    // For legacy clients/servers, we fall back to the old IPv4 comparison check if the token has one
    elseif ($player_ipv4 !== null && $player_ipv4 !== '' && $token['player_ipv4'] === $player_ipv4) {
      $this->logger->info('Successfully consumed token using player IPv4 match', [
        'callsign' => $callsign,
      ]);
      return true;
    }
    // If neither method was successful, fail the authentication attempt
    else {
      $this->logger->error('Authentication token mismatch', [
        'callsign' => $callsign,
        'token_ip' => $token['player_ipv4'],
        'actual_ip' => $player_ipv4,
        'token_host' => $token['server_host'],
        'actual_host' => $server_host,
        'token_port' => $token['server_port'],
        'actual_port' => $server_port,
      ]);
      return false;
    }
  }

  public function delete_stale(): void
  {
    try {
      $stmt = $this->pdo->prepare('DELETE FROM auth_tokens WHERE DATE_ADD(when_created, INTERVAL :token_lifetime SECOND) <= NOW()');
      $stmt->bindValue('token_lifetime', $this->token_lifetime, PDO::PARAM_INT);
      $stmt->execute();
    } catch (PDOException $e) {
      $this->logger->error('Failed purging stale authentication tokens', ['error' => $e->getMessage()]);
    }
  }
}
