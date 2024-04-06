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

namespace App\DatabaseHelper;

use DateTimeImmutable;
use DateTimeZone;
use Exception;
use League\Config\Configuration;
use Monolog\Logger;
use PDO;
use PDOException;
use Random\RandomException;

class SessionHelper
{
  // Maximum duration, in hours, that a session can exist
  private int $session_max_lifespan;

  // Maximum duration, in hours, that a session can be unused before it is considered stale
  private int $session_max_idle;

  public function __construct(private readonly PDO $pdo, Configuration $config, private readonly Logger $logger)
  {
    $this->session_max_lifespan = $config->get('session.max_lifespan');
    $this->session_max_idle = $config->get('session.max_idle');
  }

  // Create a new session
  public function create(int $user_id, string $username): array|null
  {
    try {
      // Generate a session ID
      $session_id = bin2hex(random_bytes(32));
      // This will be roughly correct, though we could use the when_created value from the created record below
      $session_expiration = (new DateTimeImmutable("+$this->session_max_lifespan hour", new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

      // Store the session in the database
      $statement = $this->pdo->prepare('INSERT INTO user_sessions (session_id, user_id, username) VALUE (:session_id, :user_id, :username)');
      $statement->bindValue('session_id', $session_id);
      $statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
      $statement->bindValue('username', $username);
      $statement->execute();

      // Return the session information
      return [
        'session_id' => $session_id,
        'user_id' => $user_id,
        'username' => $username,
        'session_expiration' => $session_expiration
      ];
    } catch (RandomException|PDOException|Exception $e) {
      $this->logger->error('Failed to create a session', ['exception_type' => get_class($e), 'error' => $e->getMessage()]);
      return null;
    }
  }

  // Get information about a session
  public function get_one(string $session_id): array|null
  {
    try {
      // Look up session, verifying that the session isn't expired or stale
      $statement = $this->pdo->prepare('SELECT user_id, username, DATE_ADD(when_created, INTERVAL :lifespan_hours HOUR) as session_expiration FROM user_sessions WHERE session_id = :session_id AND DATE_ADD(when_created, INTERVAL :lifespan_hours HOUR) > NOW() AND DATE_ADD(last_used, INTERVAL :idle_hours HOUR) > NOW()');
      $statement->bindValue('session_id', $session_id);
      $statement->bindValue('lifespan_hours', $this->session_max_lifespan, PDO::PARAM_INT);
      $statement->bindValue('idle_hours', $this->session_max_idle, PDO::PARAM_INT);
      $statement->execute();
      $session = $statement->fetch();

      // If we didn't find a valid session, bail out here
      if (!$session) {
        return null;
      }

      // Update the last_used value of this session
      $statement = $this->pdo->prepare('UPDATE user_sessions SET last_used = NOW() WHERE session_id = :session_id');
      $statement->bindValue('session_id', $session_id);
      $statement->execute();

      // Return the session information
      return $session;
    } catch (PDOException $e) {
      $this->logger->error('Failed to fetch a session', ['error' => $e->getMessage()]);
      return null;
    }
  }

  // Delete a session
  public function delete(string $session_id): bool
  {
    try {
      // Try to delete a session
      $statement = $this->pdo->prepare('DELETE FROM user_sessions WHERE session_id = :session_id');
      $statement->bindValue('session_id', $session_id);
      $statement->execute();

      // If we had at least one result (and should only be one, because... unique values), return successful
      return $statement->rowCount() > 0;
    } catch (PDOException $e) {
      $this->logger->error('Failed to delete a session', ['error' => $e->getMessage()]);
      return false;
    }
  }
}
