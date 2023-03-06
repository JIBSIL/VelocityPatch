package com.velocitypowered.proxy.crypto;

import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.config.VelocityConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ServerHashing {

    private final VelocityServer server;

    public ServerHashing(VelocityServer server) {
        this.server = server;
    }

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
