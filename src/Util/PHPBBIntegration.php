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

use League\Config\Configuration;
use Monolog\Logger;
use PDO;
use PDOException;
use Redis;

class PHPBBIntegration
{
  protected string $phpbb_database;
  protected string $phpbb_prefix;

  protected $passwords_manager;

  protected array $login_config;

  public function __construct(Configuration $config, protected PDO $pdo, protected Redis $redis, protected Logger $logger)
  {
    // TODO: Move most of this to a separate method that is called by methods that require the extra functionality.

    // Expose some variables to the global scope so that phpbb files we include can use them
    global $phpbb_root_path, $phpEx, $phpbb_container;
    $phpbb_root_path = $config->get('phpbb.root_path');
    $this->phpbb_database = $config->get('phpbb.database');
    $this->phpbb_prefix = $config->get('phpbb.prefix');
    $this->login_config = $config->get('login');

    define('IN_PHPBB', true);
    $phpEx = 'php';
    require($phpbb_root_path . 'includes/startup.' . $phpEx);
    require($phpbb_root_path . 'phpbb/class_loader.' . $phpEx);
    $phpbb_class_loader = new \phpbb\class_loader('phpbb\\', "{$phpbb_root_path}phpbb/", $phpEx);
    $phpbb_class_loader->register();
    $phpbb_config_php_file = new \phpbb\config_php_file($phpbb_root_path, $phpEx);
    extract($phpbb_config_php_file->get_all());
    @define('PHPBB_ENVIRONMENT', 'production');
    $phpbb_container_builder = new \phpbb\di\container_builder($phpbb_root_path, $phpEx);
    $phpbb_container = $phpbb_container_builder->with_config($phpbb_config_php_file)->get_container();
    $phpbb_container->get('request')->enable_super_globals();
    include($phpbb_root_path.'includes/functions.'.$phpEx);
    //include($phpbb_root_path.'includes/functions_compatibility.'.$phpEx);
    $this->passwords_manager = $phpbb_container->get('passwords.manager');
    include($phpbb_root_path.'includes/utf/utf_tools.'.$phpEx);
  }

  public function authenticate_player(string $username, string $password): array
  {
    // If too many attempts have been made and the user has been locked out, bail out here
    $key_lockout = "CENTRAL:AUTH_LOCKOUT:{$_SERVER['REMOTE_ADDR']}";
    try {
      if ($this->redis->exists($key_lockout)) {
        return [
          'error' => 'Too many failed login attempts. Temporarily locked out.'
        ];
      }
    } catch (\RedisException $e) {
      $this->logger->error('Failed to read from redis.', ['error' => $e->getMessage(), 'key' => $key_lockout]);
    }

    // Clean up UTF-8 characters
    $username_clean = utf8_clean_string($username);

    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT user_id, user_password, username FROM {$this->phpbb_database}.{$this->phpbb_prefix}users WHERE username_clean = :username_clean AND user_inactive_reason = 0");
      $statement->bindParam('username_clean', $username_clean);
      $statement->execute();
      $user = $statement->fetch();
    } catch(PDOException $e) {
      $this->logger->error('Database error when trying to fetch user information for authentication.', ['error' => $e->getMessage(), 'username' => $username]);
    }

    // If the user is registered and the password hash matches, we're good!
    // NOTE: I decided against counting failed logins to a user that doesn't exist towards the lockout. This is to
    // prevent players that switch their name to an unregistered user but don't clear out their password from being
    // locked out.
    if ($user) {
      // TODO: Should we block a range of IPv6 addresses instead of just the exact IP?
      $key_login_attempts = "CENTRAL:AUTH_ATTEMPTS:{$_SERVER['REMOTE_ADDR']}";

      // User exists, valid password
      if ($this->passwords_manager->check($password, $user['user_password'])) {
        // Check if the hash needs to be updated
        // TODO: Test upgrading hashes
        if ($this->passwords_manager->convert_flag || strlen($user['user_password']) == 32) {
          $new_hash = $this->passwords_manager->hash($password);

          try {
            $statement = $this->pdo->prepare("UPDATE {$this->phpbb_database}.{$this->phpbb_prefix}users SET user_password = :user_password WHERE user_id = :user_id");
            $statement->bindParam('user_password', $new_hash);
            $statement->bindParam('user_id', $user['user_id'], PDO::PARAM_INT);
            $statement->execute();
            // TODO: Check if this works. Some database drivers don't support this.
            if ($statement->rowCount() != 1) {
              $this->logger->error('Failed to update password hash algorithm.', ['username' => $username]);
            } else {
              $this->logger->info('Successfully upgraded password hash algorithm.', ['username' => $username]);
            }
          } catch (PDOException $e) {
            $this->logger->error('Database error when trying to update password hash algorithm.', ['error' => $e->getMessage(), 'username' => $username]);
          }
        }

        // Reset login attempts
        try {
          $this->redis->del($key_login_attempts);
        } catch (\RedisException $e) {
          $this->logger->error('Failed to delete from redis.', ['error' => $e->getMessage(), 'key' => $key_login_attempts]);
        }

        return [
          'bzid' => $user['user_id'],
          'callsign' => $user['username']
        ];
      }
      // User exists, invalid password
      else {
        try {
          // Set a redis value with the maximum failed attempts, if it doesn't exist
          if ($this->redis->setnx($key_login_attempts, $this->login_config['max_failed_attempts'])) {
            // Set the key to expire after the attempt duration expires
            $this->redis->expire($key_login_attempts, $this->login_config['attempt_duration']);
          }
          // Decrement the attempts remaining
          $this->redis->decr($key_login_attempts);
          // If we've run out of attempts, lock the user out
          if ($this->redis->get($key_login_attempts) <= 0) {
            if ($this->redis->setnx($key_lockout, 1)) {
              $this->redis->expire($key_lockout, $this->login_config['lockout_duration']);
              return [
                'error' => 'Too many failed login attempts. Temporarily locked out.'
              ];
            }
          }
        } catch (\RedisException $e) {
          $this->logger->error('Failed to write to redis.', ['error' => $e->getMessage(), 'key' => $key_login_attempts]);
        }
      }
    }

    return [
      'error' => 'Invalid username or password'
    ];
  }

  public function get_user_id_by_username(string $username): int|null
  {
    // Clean up UTF-8 characters
    $username_clean = utf8_clean_string($username);

    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT user_id FROM {$this->phpbb_database}.{$this->phpbb_prefix}users WHERE username_clean = :username_clean AND user_inactive_reason = 0");
      $statement->bindParam('username_clean', $username_clean);
      $statement->execute();
      $user = $statement->fetch();
      return $user['user_id'];
    } catch(PDOException $e) {
      $this->logger->error('Database error when trying to fetch user information for ID lookup.', ['error' => $e->getMessage(), 'username' => $username]);
    }

    return null;
  }

  public function get_username_by_user_id(int $user_id): string|null
  {
    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT username_clean FROM {$this->phpbb_database}.{$this->phpbb_prefix}users WHERE user_id = :user_id AND user_inactive_reason = 0");
      $statement->bindParam('user_id', $user_id, PDO::PARAM_INT);
      $statement->execute();
      $user = $statement->fetch();
      return $user['username_clean'];
    } catch(PDOException $e) {
      $this->logger->error('Database error when trying to fetch user information for username lookup.', ['error' => $e->getMessage(), 'user_id' => $user_id]);
    }

    return null;
  }

  public function get_groups_by_user_id(int $user_id): array|null
  {
    // Try to get the group membership information for this user
    try {
      // NOTE: The phpbb "Exempt group leader from permissions" group setting sets group_skip_auth to 1, so we can use
      // that to prevent leaders from being a member of a group. Type 3 groups are the built-in groups, of which we only
      // allow the use of the REGISTERED group.
      $statement = $this->pdo->prepare("SELECT g.group_name FROM {$this->phpbb_database}.{$this->phpbb_prefix}groups g INNER JOIN {$this->phpbb_database}.{$this->phpbb_prefix}user_group ug ON ug.group_id = g.group_id WHERE ug.user_id = :user_id AND ug.user_pending = 0 AND (group_type < 3 OR group_name = 'REGISTERED') AND NOT (g.group_skip_auth = 1 AND ug.group_leader = 1)");
      $statement->bindValue('user_id', $user_id, PDO::PARAM_INT);
      $statement->execute();
      $groups = [];
      while ($row = $statement->fetch()) {
        $groups[] = $row['group_name'];
      }
      if (sizeof($groups) > 0) {
        return $groups;
      }
    } catch (PDOException $e) {
      $this->logger->error('Database error when trying to fetch group list for user.', ['error' => $e->getMessage(), 'user_id' => $user_id]);
    }

    return null;
  }

  public function get_group_by_id(int $group_id): string|null
  {
    // Try to get the group membership information for this user
    try {
      $statement = $this->pdo->prepare("SELECT group_name FROM {$this->phpbb_database}.{$this->phpbb_prefix}groups WHERE group_id = :group_id AND (group_type < 3 OR group_name = 'REGISTERED')");
      $statement->bindValue('group_id', $group_id, PDO::PARAM_INT);
      $statement->execute();
      $row = $statement->fetch();
      if ($row) {
        return $row['group_name'];
      }
    } catch (PDOException $e) {
      $this->logger->error('Database error when trying to fetch group name.', ['error' => $e->getMessage(), 'group_id' => $group_id]);
    }

    return null;
  }

  public function get_group_id_by_name(string $group_name): int|null
  {
    // Try to get the group membership information for this user
    try {
      $statement = $this->pdo->prepare("SELECT group_id FROM {$this->phpbb_database}.{$this->phpbb_prefix}groups WHERE group_name = :group_name AND (group_type < 3 OR group_name = 'REGISTERED')");
      $statement->bindValue('group_name', $group_name);
      $statement->execute();
      $row = $statement->fetch();
      if ($row) {
        return $row['group_id'];
      }
    } catch (PDOException $e) {
      $this->logger->error('Database error when trying to fetch group id.', ['error' => $e->getMessage(), 'group_name' => $group_name]);
    }

    return null;
  }
}
