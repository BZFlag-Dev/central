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

namespace App\Controller\v1\Schema;

use OpenApi\Attributes as OA;

#[OA\Schema(
  schema: 'error',
  required: ['type', 'code', 'message'],
  properties: [
    new OA\Property(property: 'type', description: 'The type (or category) of the error', type: 'string', enum: ErrorType::class),
    new OA\Property(property: 'errors', description: 'A array of human-readable details about the error response.', type: 'array', items: new OA\Items(type: 'string')),
  ]
)]
class ErrorSchema
{
  public static function getJSON(ErrorType $type, array $errors): string
  {
    return json_encode([
      'type' => $type,
      'errors' => $errors
    ]);
  }
}
