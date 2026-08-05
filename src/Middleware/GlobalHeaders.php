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

namespace App\Middleware;

use Nyholm\Psr7\Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

// This middleware is used to add security and cache headers to every response
class GlobalHeaders
{
  public function __invoke(Request $request, RequestHandler $handler): Response
  {
    $response = $handler->handle($request);

    // Add HSTS header to HTTPS requests
    if ($request->getUri()->getScheme() === 'https') {
      $response = $response->withHeader('Strict-Transport-Security', 'max-age=31536000');
    }

    return $response
      // Security headers
      ->withHeader('X-Content-Type-Options', 'nosniff')
      ->withHeader('X-Frame-Options', 'DENY')
      ->withHeader('X-XSS-Protection', '1; mode=block')
      ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), fullscreen=(), autoplay=(), payment=(), usb=(), bluetooth=(), serial=(), gyroscope=(), accelerometer=(), magnetometer=(), picture-in-picture=(), display-capture=(), encrypted-media=(), interest-cohort=()')
      // Cache headers
      ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
      ->withHeader('Pragma', 'no-cache')
      ->withHeader('Expires', '0');
  }
}
