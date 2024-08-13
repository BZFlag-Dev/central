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

use Monolog\Logger;
use PDO;
use PDOException;
use Random\RandomException;

readonly class HostingKeysHelper
{
  public function __construct(private PDO $pdo, private Logger $logger)
  {
  }

  public function create(string $host, int $user_id): ?string
  {
    try {
      // Generate a key
      $key_string = bin2hex(random_bytes(20));

      // Store it
      $statement = $this->pdo->prepare('INSERT INTO hosting_keys (key_string, host, user_id) VALUES (:key_string, :host, :user_id)');
      $statement->bindValue('key_string', $key_string);
      $statement->bindValue('host', $host);
      $statement->bindValue('user_id', $user_id);

      // If we were able to store the key, return the generated string
      if ($statement->execute()) {
        return $key_string;
      }
    } catch (RandomException $e) {
      $this->logger->critical('Failed to generate hosting key', ['error' => $e->getMessage()]);
    } catch (PDOException $e) {
      $this->logger->critical('Failed to store hosting key', ['error' => $e->getMessage()]);
    }

    return null;
  }

  public function get_one_by_key(string $key_string): ?array
  {
    try {
      $statement = $this->pdo->prepare('SELECT id, host, user_id FROM hosting_keys WHERE key_string = :key_string');
      $statement->bindValue(':key_string', $key_string);
      $statement->execute();
      $row = $statement->fetch();
      if ($row !== false) {
        return $row;
      } else {
        return null;
      }
    } catch (PDOException $e) {
      $this->logger->error('Failed to fetch hosting key.', ['error' => $e->getMessage()]);
    }

    return null;
  }

  public function get_many_by_user(int $user_id): ?array
  {
    try {
      $statement = $this->pdo->prepare('SELECT id, key_string, host FROM hosting_keys WHERE user_id = :user_id');
      $statement->bindValue(':user_id', $user_id, PDO::PARAM_INT);
      $statement->execute();
      $keys = $statement->fetchAll();
      if (sizeof($keys) > 0) {
        return $keys;
      }
    } catch (PDOException $e) {
      $this->logger->error('Failed to fetch hosting keys.', ['error' => $e->getMessage()]);
    }

    return null;
  }

  public function delete(int $id, int $user_id): bool
  {
    try {
      $statement = $this->pdo->prepare('DELETE FROM hosting_keys WHERE id = :id AND user_id = :user_id');
      $statement->bindValue('id', $id);
      $statement->bindValue('user_id', $user_id);
      return $statement->execute();
    } catch (PDOException $e) {
      $this->logger->critical('Failed to delete hosting key.', ['error' => $e->getMessage()]);
    }

    return false;
  }
}
