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

namespace Util;

use App\Util\Valid;
use PHPUnit\Framework\TestCase;

final class ValidTest extends TestCase
{
  public function testIsValidHostname(): void
  {
    $this->assertTrue(Valid::serverHostname('example.com'));
    $this->assertTrue(Valid::serverHostname('something.example.com'));
    $this->assertTrue(Valid::serverHostname('123.example.com'));
    $this->assertTrue(Valid::serverHostname('abc.123.example.com'));
    $this->assertTrue(Valid::serverHostname('example.co.uk'));
    $this->assertTrue(Valid::serverHostname('xn--kxae4bafwg.xn--pxaix.gr'));
  }

  public function testIsNotValidHostname(): void
  {
    $this->assertFalse(Valid::serverHostname(''));
    $this->assertFalse(Valid::serverHostname('example'));
    $this->assertFalse(Valid::serverHostname('192.168.1.1'));
    $this->assertFalse(Valid::serverHostname('2001:db8::1'));
    $this->assertFalse(Valid::serverHostname('example.com.'));
    $this->assertFalse(Valid::serverHostname('example'));
    $this->assertFalse(Valid::serverHostname('ουτοπία.δπθ.gr'));
  }

  public function testIsValidServerPort(): void
  {
    $this->assertTrue(Valid::serverPort(5154));
    $this->assertTrue(Valid::serverPort(1));
    $this->assertTrue(Valid::serverPort(65535));
  }

  public function testIsNotValidServerPort(): void
  {
    $this->assertFalse(Valid::serverPort(0));
    $this->assertFalse(Valid::serverPort(65536));
    $this->assertFalse(Valid::serverPort(-5));
  }

  public function testIsValidServerProtocol(): void
  {
    $this->assertTrue(Valid::serverProtocol('BZFS0221'));
    $this->assertTrue(Valid::serverProtocol('BZFS9999'));
    $this->assertTrue(Valid::serverProtocol('BZFS0000'));
    $this->assertTrue(Valid::serverProtocol('TEST1234'));
  }

  public function testIsNotValidServerProtocol(): void
  {
    $this->assertFalse(Valid::serverProtocol(''));
    $this->assertFalse(Valid::serverProtocol('TEST1'));
    $this->assertFalse(Valid::serverProtocol('test1234'));
    $this->assertFalse(Valid::serverProtocol('T3ST1234'));
    $this->assertFalse(Valid::serverProtocol('1234TEST'));
    $this->assertFalse(Valid::serverProtocol('BZFS12345'));
  }

  public function testIsValidServerGameInfo(): void
  {
    $this->assertTrue(Valid::serverGameInfo('0000003a000300000000000000000000c800c800c800c800c800c800c8'));
    $this->assertTrue(Valid::serverGameInfo('0001007a00030000003200000000000032000000190019000000000019'));
    $this->assertTrue(Valid::serverGameInfo('000104fa0004000000c800000000000050000004280428000000000128'));
  }

  public function testIsNotValidServerGameInfo(): void
  {
    $this->assertFalse(Valid::serverGameInfo(''));
    $this->assertFalse(Valid::serverGameInfo('test'));
    $this->assertFalse(Valid::serverGameInfo(str_repeat('1234567890', 26)));
  }

  public function testIsValidServerDescription(): void
  {
    $this->assertTrue(Valid::serverDescription('This is just a test!'));
    $this->assertTrue(Valid::serverDescription('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+[]{}\\|;:\'",<.>/?`~'));
  }

  public function testIsNotValidServerDescription(): void
  {
    $this->assertFalse(Valid::serverDescription(str_repeat('1234567890', 26)));
    $this->assertFalse(Valid::serverDescription('=Þ'));
    $this->assertFalse(Valid::serverDescription('🎮'));
    $this->assertFalse(Valid::serverDescription('Neúspech'));
    $this->assertFalse(Valid::serverDescription('провал'));
  }
}
