BZFlag Central Services v3
==========================


Requirements
------------

* Apache
* PHP 8.2 FPM
* Composer
* MariaDB
* Redis
* An existing phpBB installation

Installation
------------

Install dependencies:
```bash
composer install --no-dev
```

Ensure that PHP can write to var/log/:
```bash
sudo chown www-data:www-data var/log/
```

Create a config.php file at the top level of the source with at least the following, adjusting values as needed:
```php
<?php

return [
  'legacy_host' => 'my.bzflag.whatever',
  'phpbb' => [
    'root_path' => '/var/www/forum/',
    'database' => 'forum',
  ],
  'database' => [
    'database' => 'central',
    'username' => 'central',
    'password' => 'PutPasswordHere'
  ]
];
```

See public/index.php for additional configuration options.

Database Setup
--------------

This assumes the phpbb database is 'forum' with a prefix of 'phpbb_', the central services database is 'central', and
the central services user is 'central'.

```mysql
GRANT SELECT, INSERT, UPDATE, DELETE ON central.* TO central@localhost;
GRANT SELECT ON forum.phpbb_groups TO central@localhost;
GRANT SELECT ON forum.phpbb_user_group TO central@localhost;
GRANT SELECT, UPDATE ON forum.phpbb_users TO central@localhost;
```

Import structure.sql into the 'central' database.
