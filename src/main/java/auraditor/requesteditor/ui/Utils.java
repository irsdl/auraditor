/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Static utility methods 
 * 
 * @author adetlefsen
 */
public class Utils {

    public static String urlDecode(String input) {
        try {
            String decoded = URLDecoder.decode(input, "UTF-8");
            // Handle any remaining formatting issues with multiline JSON
            // Normalize line endings and ensure proper JSON formatting
            return normalizeJsonString(decoded);
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }

    /**
     * Normalize JSON string to handle multiline beautified JSON properly
     */
    private static String normalizeJsonString(String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return jsonString;
        }

        // Normalize different line ending types to Unix-style \n
        // This is crucial for JSON that was created on Windows but processed on Unix
        String normalized = jsonString.replace("\r\n", "\n").replace("\r", "\n");

        // Handle any potential double-encoding issues where newlines might be encoded twice
        // Sometimes %0A might appear even after URLDecoder.decode() if there was double encoding
        normalized = normalized.replace("%0A", "\n").replace("%0D", "\r");

        // Ensure the string doesn't have trailing whitespace that could break JSON parsing
        return normalized.trim();
    }

    public static String urlEncode(String input) {
        try {
            return URLEncoder.encode(input, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new AssertionError("UTF-8 not supported", ex);
        }
    }
}
