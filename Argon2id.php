<?php
/**
 * Plugin Name: MU Native Argon2id Password Hashing
 * Description: Dynamically upgrades legacy MD5/phpass hashes to secure PHP native Argon2id (with a Bcrypt fallback).
 * Version: 1.0.0
 * Author: Your Name
 */

// STEP 1: Security check to block users from directly opening this file in a browser.
// WHY: If an attacker triggers this file directly via a URL, executing it outside of 
// WordPress can reveal critical path configurations, cause server errors, or expose 
// system behavior that aids in exploiting the environment.
if (!defined('ABSPATH')) {
    exit;
}

/**
 * STEP 2: Override how WordPress CREATES a new password hash.
 * This runs when users register, reset, or update their passwords.
 */
if (!function_exists('wp_hash_password')) {
    function wp_hash_password($password) {
        
        // STEP 2a: Detect if the server actually supports Argon2id.
        // If it doesn't, automatically fall back to PASSWORD_DEFAULT (Bcrypt) so logins don't break.
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        
        // STEP 2b: Configure the resource constraints if using Argon2id.
        // This is where we demand BOTH the deliberate "timeout" and the massive "desk space" (RAM).
        $options = [
            'memory_cost' => 65536, // Forces the machine to use 64 MB of RAM per attempt
            'time_cost'   => 4,     // Forces the processor to make 4 execution passes
            'threads'     => 2,     // Splits the work across 2 parallel processing threads
        ];

        // Generate the high-security hash string
        return password_hash($password, $algo, $options);
    }
}

/**
 * STEP 3: Override how WordPress CHECKS an entered password at login.
 * This acts as a bridge to seamlessly handle old MD5 users and new Argon2id users.
 */
if (!function_exists('wp_check_password')) {
    function wp_check_password($password, $hash, $user_id = '') {
        
        // STEP 3a: Check if the stored database hash is already a modern PHP native hash (Argon2id or Bcrypt)
        if (password_get_info($hash)['algo'] !== 0) {
            
            // Verify the entered password against the modern algorithm requirements
            $is_valid = password_verify($password, $hash);
            
            // Target Algorithm: We prefer Argon2id if available, otherwise Bcrypt
            $preferred_algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
            
            // If the password matches but your server's security settings or RAM limits changed, 
            // recalculate and upgrade the hash seamlessly without bothering the user.
            if ($is_valid && password_needs_rehash($hash, $preferred_algo)) {
                wp_set_password($password, $user_id);
            }
            
            // Return the true/false result through standard WordPress security filters
            return apply_filters('check_password', $is_valid, $password, $hash, $user_id);
        }

        // STEP 3b: Fallback mode if the stored database hash is still an old MD5/phpass string
        global $wp_hasher;

        // Fire up the legacy WordPress core hashing class to read the old format
        if (empty($wp_hasher)) {
            require_once ABSPATH . WPINC . '/class-phpass.php';
            $wp_hasher = new PasswordHash(8, true);
        }

        // Check the typed password against the old MD5 format
        $is_valid = $wp_hasher->CheckPassword($password, $hash);

        // MIGRATION STEP: If the legacy password is correct, immediately overwrite the 
        // old MD5 in the database with a fresh, secure Argon2id hash on the fly.
        if ($is_valid && !empty($user_id)) {
            wp_set_password($password, $user_id);
        }

        // Return the final login approval/denial
        return apply_filters('check_password', $is_valid, $password, $hash, $user_id);
    }
}