<?php
/**
 * Plugin Name: MU Native Bcrypt Password Hashing
 * Description: Dynamically upgrades legacy MD5/phpass hashes to secure PHP native bcrypt.
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
        // PASSWORD_DEFAULT utilizes the server's native bcrypt algorithm.
        // This instantly introduces the deliberate mathematical "timeout."
        return password_hash($password, PASSWORD_DEFAULT);
    }
}

/**
 * STEP 3: Override how WordPress CHECKS an entered password at login.
 * This acts as a bridge to seamlessly handle both old MD5 users and new Bcrypt users.
 */
if (!function_exists('wp_check_password')) {
    function wp_check_password($password, $hash, $user_id = '') {
        
        // STEP 3a: Check if the stored database hash is already a modern bcrypt hash
        if (password_get_info($hash)['algo'] !== 0) {
            
            // Verify the entered password against the modern bcrypt hash
            $is_valid = password_verify($password, $hash);
            
            // If the password matches but your server's security settings upgraded, 
            // recalculate the hash seamlessly without bothering the user.
            if ($is_valid && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
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
        // old MD5 in the database with a fresh, secure Bcrypt hash on the fly.
        if ($is_valid && !empty($user_id)) {
            wp_set_password($password, $user_id);
        }

        // Return the final login approval/denial
        return apply_filters('check_password', $is_valid, $password, $hash, $user_id);
    }
}