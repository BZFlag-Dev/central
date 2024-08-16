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
  protected array $login_config;

  public function __construct(Configuration $config, protected PDO $pdo, protected Redis $redis, protected Logger $logger)
  {
    // Store some configuration information
    $this->phpbb_database = $config->get('phpbb.database');
    $this->phpbb_prefix = $config->get('phpbb.prefix');
    $this->login_config = $config->get('login');

    // Expose some variables to the global scope so that phpBB files we include can use them
    global $phpbb_root_path, $phpEx;
    $phpbb_root_path = $config->get('phpbb.root_path');
    $phpEx = 'php';

    // Tell phpBB files that we're in phpBB, so they don't bail out when we include them
    define('IN_PHPBB', true);
  }

  /**
   * Add the database name and table prefix to a database table name
   * @param string $table Base name of the table
   * @return string The prefixed table name
   */
  private function phpbb_table(string $table): string
  {
    return "$this->phpbb_database.$this->phpbb_prefix$table";
  }

  /**
   * Wrapper around phpBB's utf8_clean_string function that brings in the needed includes on first use
   * @param string $string The UTF-8 string to clean/normalize
   * @return string The cleaned/normalized string
   */
  private function utf8_clean_string(string $string): string
  {
    if (!function_exists('utf8_clean_string')) {
      global $phpbb_root_path, $phpEx;

      // Pull in functions for handling UTF-8 normalization
      require($phpbb_root_path.'includes/utf/utf_tools.'.$phpEx);
    }

    return utf8_clean_string($string);
  }

  //

  /**
   * Return phpBB's password manager. This will initialize it on demand.
   * @return \phpbb\passwords\manager phpBB's password manager
   */
  private function get_passwords_manager(): \phpbb\passwords\manager
  {
    static $passwords_manager;

    if (!$passwords_manager) {
      global $phpbb_root_path, $phpEx;

      // Load a minimal config so that we can pass something to phpBB classes
      // Note: In the files we include, only phpbb\passwords\driver::unique_id() uses the config, and that is only called
      // if get_random_salt() fails to get enough entropy from /dev/urandom
      require($phpbb_root_path.'phpbb/config/config.'.$phpEx);
      $phpbb_config = new \phpbb\config\config([
        'rand_seed' => 0,
        'rand_seed_last_update' => 0
      ]);

      // This is used by password drivers
      require($phpbb_root_path.'phpbb/passwords/driver/driver_interface.'.$phpEx);
      require($phpbb_root_path.'phpbb/passwords/driver/rehashable_driver_interface.'.$phpEx);
      require($phpbb_root_path.'phpbb/passwords/driver/base.'.$phpEx);
      require($phpbb_root_path.'phpbb/passwords/driver/base_native.'.$phpEx);

      // Included because argon2id extends this
      require($phpbb_root_path.'phpbb/passwords/driver/argon2i.'.$phpEx);

      // This is the currently used modern hash
      require($phpbb_root_path.'phpbb/passwords/driver/argon2id.'.$phpEx);

      // Included for handling any ancient hashes
      require($phpbb_root_path.'phpbb/passwords/driver/salted_md5.'.$phpEx);

      // Some extra types that are tried as defaults
      require($phpbb_root_path.'phpbb/passwords/driver/bcrypt.'.$phpEx);
      require($phpbb_root_path.'phpbb/passwords/driver/bcrypt_2y.'.$phpEx);
      require($phpbb_root_path.'phpbb/passwords/driver/phpass.'.$phpEx);

      // Password driver helper stuff
      require($phpbb_root_path.'phpbb/passwords/driver/helper.'.$phpEx);
      $phpbb_password_driver_helper = new \phpbb\passwords\driver\helper($phpbb_config);

      // Set up hashing algorithm drivers
      // TODO: Possibly eliminate some of these if they aren't used/needed (or add others to handle old hashes that need
      //   to be updated in the database)
      $hashing_algorithms = [
        'passwords.driver.argon2i' => new \phpbb\passwords\driver\argon2i($phpbb_config, $phpbb_password_driver_helper),
        'passwords.driver.argon2id' => new \phpbb\passwords\driver\argon2id($phpbb_config, $phpbb_password_driver_helper),
        'passwords.driver.bcrypt_2y' => new \phpbb\passwords\driver\bcrypt_2y($phpbb_config, $phpbb_password_driver_helper),
        'passwords.driver.bcrypt' => new \phpbb\passwords\driver\bcrypt($phpbb_config, $phpbb_password_driver_helper),
        'passwords.driver.salted_md5' => new \phpbb\passwords\driver\salted_md5($phpbb_config, $phpbb_password_driver_helper),
        'passwords.driver.phpass' => new \phpbb\passwords\driver\phpass($phpbb_config, $phpbb_password_driver_helper),
      ];

      // Pull in and create the passwords helper
      require($phpbb_root_path.'phpbb/passwords/helper.'.$phpEx);
      $phpbb_password_helper = new \phpbb\passwords\helper();

      // Sets the priority for the default hashing algorithm, with the top being higher priority. The code uses the first
      // one that is supported.
      $defaults = [
        'passwords.driver.argon2id',
        'passwords.driver.argon2i',
        'passwords.driver.bcrypt_2y',
        'passwords.driver.bcrypt',
        'passwords.driver.salted_md5',
        'passwords.driver.phpass'
      ];
      require($phpbb_root_path.'phpbb/passwords/manager.'.$phpEx);
      $passwords_manager = new \phpbb\passwords\manager($phpbb_config, $hashing_algorithms, $phpbb_password_helper, $defaults);
    }

    return $passwords_manager;
  }

  /**
   * Attempt to authenticate a player against the phpBB user database. This also rate limits failed attempts to block
   * attacks.
   * @param string $username The player's username/callsign
   * @param string $password The player's password
   * @return array Information about the result of authenticating, failure or otherwise
   */
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
    $username_clean = $this->utf8_clean_string($username);

    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT user_id, user_password, username FROM {$this->phpbb_table('users')} WHERE username_clean = :username_clean AND user_inactive_reason = 0");
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
      $passwords_manager = $this->get_passwords_manager();
      if ($passwords_manager->check($password, $user['user_password'])) {
        // Check if the hash needs to be updated
        // TODO: Test upgrading hashes
        if ($passwords_manager->convert_flag || strlen($user['user_password']) == 32) {
          $new_hash = $passwords_manager->hash($password);
          if ($new_hash !== false && strlen($new_hash) > 0) {
            try {
              $statement = $this->pdo->prepare("UPDATE {$this->phpbb_table('users')} SET user_password = :user_password WHERE user_id = :user_id");
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
          } else {
            $this->logger->error('Failed to generated updated password hash algorithm.', ['username' => $username]);
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
      'error' => 'Username or password is incorrect'
    ];
  }

  /**
   * Get the phpBB user ID (also known as BZID) associated with a username/callsign
   * @param string $username The username/callsign of the player
   * @return int|null The user ID of the user, or null if we did not find a matching user
   */
  public function get_user_id_by_username(string $username): int|null
  {
    // Clean up UTF-8 characters
    $username_clean = $this->utf8_clean_string($username);

    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT user_id FROM {$this->phpbb_table('users')} WHERE username_clean = :username_clean AND user_inactive_reason = 0");
      $statement->bindParam('username_clean', $username_clean);
      $statement->execute();
      $user = $statement->fetch();
      return $user['user_id'];
    } catch(PDOException $e) {
      $this->logger->error('Database error when trying to fetch user information for ID lookup.', ['error' => $e->getMessage(), 'username' => $username]);
    }

    return null;
  }

  /**
   * Get the clean (UTF-8 normalized) username associated with a user ID (BZID)
   * @param int $user_id The user ID (BZID) of the player
   * @return string|null The username, or null if we did not find a matching user
   */
  public function get_username_by_user_id(int $user_id): string|null
  {
    // Try to get user information for this user
    try {
      $statement = $this->pdo->prepare("SELECT username_clean FROM {$this->phpbb_table('users')} WHERE user_id = :user_id AND user_inactive_reason = 0");
      $statement->bindParam('user_id', $user_id, PDO::PARAM_INT);
      $statement->execute();
      $user = $statement->fetch();
      return $user['username_clean'];
    } catch(PDOException $e) {
      $this->logger->error('Database error when trying to fetch user information for username lookup.', ['error' => $e->getMessage(), 'user_id' => $user_id]);
    }

    return null;
  }

  /**
   * Returns the number of unread private messages for a user
   * @param int $user_id The user ID (BZID) of the player
   * @return int The number of unread messages. This also returns 0 if we did not find a matching user.
   */
  public function get_private_message_count_by_user_id(int $user_id): int
  {
    try {
      $statement = $this->pdo->prepare("SELECT user_new_privmsg FROM {$this->phpbb_table('users')} WHERE user_id = :user_id");
      $statement->bindParam('user_id', $user_id, PDO::PARAM_INT);
      $statement->execute();
      $user = $statement->fetch();
      if ($user) {
        return $user['user_new_privmsg'];
      }
    } catch(PDOException $e) {
      $this->logger->warning('Failed to get private message count.', ['user_id' => $user_id, 'error' => $e->getMessage()]);
    }

    return 0;
  }

  /**
   * Return a list of groups that a user belongs to
   * @param int $user_id The user ID (BZID) of the user
   * @return array|null A list of group names, or null if we did not find a matching user
   */
  public function get_groups_by_user_id(int $user_id): array|null
  {
    // Try to get the group membership information for this user
    try {
      // NOTE: The phpbb "Exempt group leader from permissions" group setting sets group_skip_auth to 1, so we can use
      // that to prevent leaders from being a member of a group. Type 3 groups are the built-in groups, of which we only
      // allow the use of the REGISTERED group.
      $statement = $this->pdo->prepare("SELECT g.group_name FROM {$this->phpbb_table('groups')} g INNER JOIN {$this->phpbb_table('user_group')} ug ON ug.group_id = g.group_id WHERE ug.user_id = :user_id AND ug.user_pending = 0 AND (group_type < 3 OR group_name = 'REGISTERED') AND NOT (g.group_skip_auth = 1 AND ug.group_leader = 1)");
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

  /**
   * Returns the group ID of a group
   * @param string $group_name The group name to look up
   * @return int|null The group ID, or null if the group does not exist
   */
  public function get_group_id_by_name(string $group_name): int|null
  {
    // Try to get the group membership information for this user
    try {
      $statement = $this->pdo->prepare("SELECT group_id FROM {$this->phpbb_table('groups')} WHERE group_name = :group_name AND (group_type < 3 OR group_name = 'REGISTERED')");
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
