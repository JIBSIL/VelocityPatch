/*
 * Copyright (C) 2018-2022 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.velocitypowered.proxy.crypto;

import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Hashes a server given the forwarding key, allowing for per-server forwarding secrets.
 */
public class ServerHashing {
  private final VelocityServer server;

  public ServerHashing(VelocityServer server) {
    this.server = server;
  }

  /**
   * Hashing function.
   */
  public String generateSecret(String variableKey) {
    // Concatenate the secret key and variable key
    VelocityConfiguration configuration = server.getConfiguration();
    byte[] secretKey = configuration.getForwardingSecret();
    String combinedKey = Arrays.toString(secretKey) + variableKey;

    // Hash the combined key using SHA-256
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(combinedKey.getBytes(StandardCharsets.UTF_8));

      // Convert the hash to a hexadecimal string
      StringBuilder hexString = new StringBuilder();
      for (byte b : hash) {
        hexString.append(String.format("%02x", b));
      }

      // Return the hexadecimal string as the output
      return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
      // This should never happen because SHA-256 is a standard algorithm
      throw new RuntimeException(e);
    }
  }
}
