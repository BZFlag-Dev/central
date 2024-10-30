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

use Phinx\Db\Adapter\MysqlAdapter;
use Phinx\Migration\AbstractMigration;

final class InitialStructure extends AbstractMigration
{
  /**
   * Change Method.
   *
   * Write your reversible migrations using this method.
   *
   * More information on writing migrations is available here:
   * https://book.cakephp.org/phinx/0/en/migrations.html#the-change-method
   *
   * Remember to call "create()" or "update()" and NOT "save()" when working
   * with the Table class.
   */
  public function change(): void
  {
    $servers = $this->table('servers');
    $servers
      ->addColumn('host', 'string', ['null' => false])
      ->addColumn('port', 'smallinteger', ['signed' => false, 'null' => false])
      ->addColumn('protocol', 'string', ['null' => false, 'length' => 8])
      ->addColumn('hosting_key_id', 'integer', ['signed' => false])
      ->addColumn('game_info', 'string', ['null' => false, 'length' => 255])
      ->addColumn('world_hash', 'string', ['length' => 255])
      ->addColumn('description', 'string', ['length' => 255])
      ->addColumn('owner', 'string', ['length' => 255])
      ->addColumn('build', 'string', ['length' => 255])
      ->addColumn('when_updated', 'timestamp', ['default' => 'CURRENT_TIMESTAMP', 'update' => 'CURRENT_TIMESTAMP'])
      ->addIndex(['host', 'port'], ['unique' => true])
      ->addIndex('protocol')
      ->addIndex('when_updated')
      ->create();

    $server_advert_groups = $this->table('server_advert_groups', ['id' => false, 'primary_key' => ['server_id', 'group_id']]);
    $server_advert_groups
      ->addColumn('server_id', 'integer', ['signed' => false])
      ->addColumn('group_id', 'integer', ['signed' => false, 'limit' => MysqlAdapter::INT_MEDIUM])
      ->addIndex('server_id')
      ->create();

    $hosting_keys = $this->table('hosting_keys');
    $hosting_keys
      ->addColumn('key_string', 'string', ['null' => false, 'length' => 255])
      ->addColumn('host', 'string', ['null' => false, 'length' => 255])
      ->addColumn('user_id', 'integer', ['null' => false, 'signed' => false])
      ->addIndex('key_string', ['unique' => true])
      ->addIndex('user_id')
      ->create();

    $auth_tokens = $this->table('auth_tokens', ['id' => false]);
    $auth_tokens
      ->addColumn('user_id', 'integer', ['null' => false, 'signed' => false])
      ->addColumn('token', 'string', ['null' => false, 'length' => 128])
      ->addColumn('player_ipv4', 'string', ['length' => 16])
      ->addColumn('server_host', 'string', ['length' => 255])
      ->addColumn('server_port', 'smallinteger', ['signed' => false])
      ->addColumn('when_created', 'timestamp', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
      ->addIndex('token', ['unique' => true])
      ->addIndex('user_id')
      ->create();

    $user_sessions = $this->table('user_sessions', ['id' => false]);
    $user_sessions
      ->addColumn('session_id', 'char', ['null' => false, 'length' => 64])
      ->addColumn('user_id', 'integer', ['null' => false, 'signed' => false])
      ->addColumn('username', 'string', ['null' => false, 'length' => 255])
      ->addColumn('when_created', 'timestamp', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
      ->addColumn('last_used', 'timestamp', ['null' => false, 'default' => 'CURRENT_TIMESTAMP'])
      ->addIndex('session_id', ['unique' => true])
      ->addIndex('user_id')
      ->create();
  }
}
