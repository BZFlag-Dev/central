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

class GameServerHelper
{
  private int $server_stale_time;

  public function __construct(private readonly PDO $pdo, private readonly Configuration $config, private readonly Logger $logger)
  {
    $this->server_stale_time = $config->get('server_stale_time');
  }

  public function get_many(string $protocol = null, string $hostname = null, int $user_id = null): array|null
  {
    // Delete stale servers
    $this->delete_stale();

    // If we have a valid session, we can look up servers advertised to groups the user belongs to
    if (!empty($user_id)) {
      $phpbb_database = $this->config->get('phpbb.database');
      $phpbb_prefix = $this->config->get('phpbb.prefix');
      $sql = "SELECT s.host as hostname, s.port, s.protocol, s.game_info, s.world_hash, s.description, s.owner FROM servers s LEFT JOIN server_advert_groups ag INNER JOIN {$phpbb_database}.{$phpbb_prefix}user_group ug ON ag.group_id = ug.group_id ON s.id = ag.server_id WHERE (ug.user_id = :user_id OR ag.server_id IS NULL)";
    } else {
      $sql = 'SELECT s.host as hostname, s.port, s.protocol, s.game_info, s.world_hash, s.description, s.owner FROM servers s LEFT JOIN server_advert_groups ag ON s.id = ag.server_id WHERE ag.server_id IS NULL';
    }

    // Don't show stale servers
    $sql .= ' AND DATE_ADD(when_updated, INTERVAL :server_stale_time SECOND) > NOW()';

    // Support filtering on the protocol and hostname
    if (!empty($protocol)) {
      $sql .= ' AND protocol = :protocol';
    }
    if (!empty($hostname)) {
      $sql .= ' AND host = :hostname';
    }

    // Add on some basic sorting
    $sql .= ' ORDER BY host ASC, port ASC';

    // Prepare and run the query, binding any needed data along the way
    try {
      $statement = $this->pdo->prepare($sql);
      $statement->bindValue(':server_stale_time', $this->server_stale_time, PDO::PARAM_INT);
      if (!empty($user_id)) {
        $statement->bindValue('user_id', $user_id);
      }
      if (!empty($protocol)) {
        $statement->bindValue('protocol', $protocol);
      }
      if (!empty($hostname !== null)) {
        $statement->bindValue('hostname', $hostname);
      }
      if ($statement->execute()) {
        return $statement->fetchAll();
      }
    } catch (PDOException $e) {
      $this->logger->critical('Failed to fetch servers', ['error' => $e->getMessage()]);
    }

    return null;
  }

  public function get_id_and_key_from_hostname_and_port(string $hostname, int $port): array|null
  {
    try {
      $statement = $this->pdo->prepare('SELECT s.id, h.key_string FROM servers s LEFT JOIN hosting_keys h ON s.hosting_key_id = h.id WHERE s.host = :hostname AND s.port = :port');
      $statement->bindValue('hostname', $hostname);
      $statement->bindValue('port', $port, PDO::PARAM_INT);
      $statement->execute();
      $server = $statement->fetch();
      if ($server) {
        return $server;
      }
    } catch (PDOException $e) {
      $this->logger->critical('Failed to lookup server', [
        'hostname' => $hostname,
        'port' => $port,
        'error' => $e->getMessage()
      ]);
    }

    return null;
  }

  public function delete(int $id): bool
  {
    try {
      $statement = $this->pdo->prepare('DELETE FROM servers WHERE id = :id');
      $statement->bindValue('id', $id, PDO::PARAM_INT);
      $statement->execute();

      $statement = $this->pdo->prepare('DELETE FROM server_advert_groups WHERE server_id = :server_id');
      $statement->bindValue('server_id', $id, PDO::PARAM_INT);
      $statement->execute();

      return true;
    } catch (PDOException $e) {
      $this->logger->critical('Failed to delete server or advert groups', [
        'id' => $id,
        'error' => $e->getMessage()
      ]);
    }

    return false;
  }

  public function delete_stale(): void
  {
    try {
      $statement = $this->pdo->prepare('DELETE FROM servers WHERE DATE_ADD(when_updated, INTERVAL :server_stale_time SECOND) <= NOW()');
      $statement->bindValue(':server_stale_time', $this->server_stale_time);
      $statement->execute();
    } catch (PDOException $e) {
      $this->logger->error('Failed to delete expired game servers: ', ['error' => $e->getMessage()]);
    }
  }
}
