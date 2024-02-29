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

namespace App\Util;

use League\Config\Configuration;
use PDO;
use PDOException;
use Redis;

class PHPBBIntegration
{
  protected string $phpbb_database;
  protected string $phpbb_prefix;

  protected $passwords_manager;

  protected array $login_config;

  public function __construct(Configuration $config, protected PDO $pdo, protected Redis $redis)
  {
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

  public function authenticate_player(string $callsign, string $password): array
  {
    // If too many attempts have been made and the user has been locked out, bail out here
    $key_lockout = "CENTRAL:AUTH_LOCKOUT:{$_SERVER['REMOTE_ADDR']}";
    try {
      if ($this->redis->exists($key_lockout)) {
        return [
          'error' => 'Too many failed login attempts. Temporarily locked out.'
        ];
      }
    } catch (\RedisException) {
      // TODO: Log errors
    }

    // Clean up UTF-8 characters
    $clean_callsign = utf8_clean_string($callsign);

    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT user_id, user_password, username FROM {$this->phpbb_database}.{$this->phpbb_prefix}users WHERE username_clean = :username_clean AND user_inactive_reason = 0");
      $statement->bindParam('username_clean', $clean_callsign);
      $statement->execute();
      $user = $statement->fetch();
    } catch(PDOException) {
      // TODO: Log errors
    }

    // If the user is registered and the password hash matches, we're good!
    if ($user) {
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
            $statement->bindParam('user_id', $row['user_id'], PDO::PARAM_INT);
            $statement->execute();
            // TODO: Check if this works. Some database drivers don't support this.
            if ($statement->rowCount() != 1) {
              // TODO: Log errors
            }

          } catch (PDOException) {
            // TODO: Log errors
          }
        }

        // Reset login attempts
        try {
          $this->redis->del($key_login_attempts);
        } catch (\RedisException) {
          // TODO: Log errors
        }

        // TODO: Actually return needed info here
        return [
          'bzid' => $user['user_id'],
          'callsign' => $user['username']
        ];
      }
      // User exists, invalid password
      else {
        try {
          // Set a redis value with the maximum failed attempts, if it doesn't exist
          if ($redis->setnx($key_login_attempts, $this->login_config['max_failed_attempts'])) {
            // Set the key to expire after the attempt duration expires
            $redis->expire($key_login_attempts, $this->login_config['attempt_duration']);
          }
          // Decrement the attempts remaining
          $redis->decr($key_login_attempts);
          // If we've run out of attempts, lock the user out
          if ($redis->get($key_login_attempts) <= 0) {
            if ($redis->setnx($key_lockout, 1)) {
              $redis->expire($key_lockout, $this->login_config['lockout_duration']);
            }
          }
        } catch (\RedisException) {
          // TODO: Log errors
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
    } catch(PDOException) {
      // TODO: Log errors
    }

    return null;
  }

  public function get_username_by_user_id(int $user_id): string|null
  {
    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT username_clean FROM {$this->phpbb_database}.{$this->phpbb_prefix}users WHERE user_id = :user_id AND user_inactive_reason = 0");
      $statement->bindParam('user_id', $user_id);
      $statement->execute();
      $user = $statement->fetch();
      return $user['username_clean'];
    } catch(PDOException) {
      // TODO: Log errors
    }

    return null;
  }
}
