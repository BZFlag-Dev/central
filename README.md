BZFlag Central
==============

The BZFlag project hosts centralized services for listing public servers and authenticating registered players. This
project is the third generation of the central services and aims to provide a legacy interface compatible with the v2
services and also provide a modern REST API with additional functionality. Another goal is support for CGNAT and, on the
REST API, IPv6, both of which are pain points with the current v2 authentication system.

Requirements
------------

* Apache
* PHP 8.2 FPM with the following extensions:
  * PDO
  * MySQL
  * Redis
  * JSON
  * mbstring
  * ctype
* Composer
* MariaDB
* Redis
* An existing phpBB installation

Installation
------------

Install dependencies:
```bash
composer install --no-dev --optimize-autoloader
composer install --no-dev -d tools
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

This assumes the phpBB database is 'forum' with a prefix of 'phpbb_', the central services database is 'central', the
central services user is 'central', and another migration account is called 'central_migration'. Adjust the below to
match your environment.

```mysql
GRANT SELECT, INSERT, UPDATE, DELETE ON central.* TO central@localhost;
GRANT SELECT ON forum.phpbb_groups TO central@localhost;
GRANT SELECT ON forum.phpbb_user_group TO central@localhost;
GRANT SELECT, UPDATE ON forum.phpbb_users TO central@localhost;

GRANT SELECT, INSERT, UPDATE, DELETE, ALTER, CREATE, DROP ON central.* TO central_migration@localhost;
```

Create a `phinx-config.php`:
```php
<?php
return [
  'database' => [
    'database' => 'central',
    'username' => 'central_migration',
    'password' => 'PutPasswordHere'
  ]
];
```

Run the migration:
```bash
php tools/vendor/bin/phinx migrate
```

Generating REST Documentation
-----------------------------

The REST API uses PHP 8 Attributes to describe the API and [zircote/swagger-php](https://github.com/zircote/swagger-php)
to generate an OpenAPI specification. [Swagger UI](https://github.com/swagger-api/swagger-ui?tab=readme-ov-file#general)
can then be used to display the API specification in a developer friendly way that allows trying it out in a browser. To
generate the specification, run the following commands:

```bash
composer -d tools install
./tools/vendor/bin/openapi src/Controller/v1 -o ../central-docs/public/v1.yaml -b vendor/autoload.php
```

Webserver Configuration
-----------------------

To allow compatibility with BZFlag versions older than 2.4.4, do not enforce HTTPS on the legacy virtual host. Remove
any such redirect from the virtual host that might be added by certbot.

To ensure that requests to the REST API are not silently upgraded from HTTP to HTTPS, do not automatically redirect
HTTP request to HTTPS, except for the /docs path. Certbot will automatically create a permanent redirect, so move that
to the <Directory> block for /docs.

```apacheconf
<VirtualHost *:80>
        ServerName my.bzflag.whatever

        DocumentRoot /var/www/central/public
        <Directory /var/www/central/public>
                Options -Indexes
                Require all granted

                RewriteEngine on
                RewriteCond %{REQUEST_FILENAME} !-f
                RewriteCond %{REQUEST_FILENAME} !-d
                RewriteRule ^ index.php [QSA,L]
        </Directory>
</VirtualHost>

<VirtualHost *:80>
        ServerName central.bzflag.whatever

        DocumentRoot /var/www/central/public
        <Directory /var/www/central/public>
                Options -Indexes
                Require all granted

                RewriteEngine on
                RewriteCond %{REQUEST_FILENAME} !-f
                RewriteCond %{REQUEST_FILENAME} !-d
                RewriteRule ^ index.php [QSA,L]
        </Directory>

        Alias /docs /var/www/central-docs/public/
        <Directory /var/www/central-docs/public/>
                Options -Indexes
                Require all granted

                # Only redirect /docs to HTTPS to prevent silent upgrades to API requests
                RewriteEngine on
                RewriteCond %{SERVER_NAME} =central.bzflag.whatever
                RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
        </Directory>
</VirtualHost>
```

License
-------
Copyright (C) 2023-2024  BZFlag & Associates

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
* public/css/bootstrap.min.css and public/css/bootstrap.min.css.map (copied during `composer install`): [MIT License](https://github.com/twbs/bootstrap/blob/main/LICENSE), Copyright (c) 2011-2024 The Bootstrap Authors
