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


License
-------
Copyright (C) 2023  BZFlag & Associates

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
details.

Some files are distributed under different licenses:
* public/js/js-cookie.min.js: [MIT License](https://github.com/js-cookie/js-cookie/blob/main/LICENSE), Copyright (c) 2018 Copyright 2018 Klaus Hartl, Fagner Brack, GitHub Contributors
* public/images/weblogin_logo.png (and other formats): [GNU LGPL 2.1](https://github.com/BZFlag-Dev/bzflag/blob/2.4/COPYING.LGPL), Copyright (c) 2024 Tim Riker
* theme toggle SVG/CSS in views/weblogin.html.twig and public/css/weblogin.css: [MIT License](https://github.com/AlfieJones/theme-toggles/blob/main/LICENSE), Copyright (c) 2021 Alfred Jones
