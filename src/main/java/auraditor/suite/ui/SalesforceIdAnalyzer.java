/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import java.util.Map;

/**
 * Helper class for analyzing Salesforce IDs (15 or 18 character format)
 *
 * Salesforce ID Structure (15 chars):
 * - Chars 0-2: Object prefix (identifies object type)
 * - Chars 3-5: Instance ID (Salesforce instance)
 * - Char 6: Reserved
 * - Chars 7-14: Record number (8-char base62)
 *
 * 18-char format adds 3-char checksum suffix for case-insensitive uniqueness
 */
public class SalesforceIdAnalyzer {

    // Base62 alphabet used by Salesforce (0-9, A-Z, a-z)
    private static final String BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int BASE62 = BASE62_ALPHABET.length();

    // Maximum value representable by 8 base62 chars: 62^8 - 1 = 218,340,105,584,895
    public static final long MAX_BASE62_8 = 218340105584895L;

    // Checksum mapping alphabet (A-Z, 0-5) - 32 characters for 5-bit values
    private static final String CHECKSUM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

    // Common Salesforce object prefixes
    // Source: https://help.salesforce.com/s/articleView?id=000385203&type=1
    private static final Map<String, String> OBJECT_PREFIXES = Map.ofEntries(
        Map.entry("001", "Account"),
        Map.entry("002", "Note"),
        Map.entry("003", "Contact"),
        Map.entry("005", "User"),
        Map.entry("006", "Opportunity"),
        Map.entry("007", "Activity"),
        Map.entry("008", "OpportunityHistory"),
        Map.entry("00D", "Organization"),
        Map.entry("00E", "UserRole"),
        Map.entry("00G", "Group"),
        Map.entry("00I", "AccountTeamMember"),
        Map.entry("00N", "CustomFieldDefinition"),
        Map.entry("00O", "Report"),
        Map.entry("00Q", "Lead"),
        Map.entry("00T", "Task"),
        Map.entry("015", "Dashboard"),
        Map.entry("500", "Case"),
        Map.entry("501", "Solution"),
        Map.entry("701", "Campaign"),
        Map.entry("800", "Contract")
    );

    /**
     * Result class containing analysis information
     */
    public static class AnalysisResult {
        public boolean valid;
        public boolean is18Char;
        public String errorMessage;
        public String id15;
        public String id18;
        public String checksum;
        public boolean checksumValid;
        public String expectedChecksum;
        public String objectPrefix;
        public String objectType;
        public String instanceId;
        public String reserved;
        public String recordNumberBase62;
        public long recordNumberDecimal;

        public AnalysisResult() {
            this.valid = false;
        }
    }

    /**
     * Analyze a Salesforce ID (15 or 18 characters)
     */
    public static AnalysisResult analyze(String input) {
        AnalysisResult result = new AnalysisResult();

        // Validate input
        if (input == null || input.trim().isEmpty()) {
            result.errorMessage = "ID cannot be empty";
            return result;
        }

        String id = input.trim();

        // Check length
        if (id.length() != 15 && id.length() != 18) {
            result.errorMessage = "Length must be 15 or 18 characters (current: " + id.length() + ")";
            return result;
        }

        // Check alphanumeric
        if (!id.matches("[A-Za-z0-9]+")) {
            result.errorMessage = "ID must contain only alphanumeric characters";
            return result;
        }

        result.is18Char = (id.length() == 18);

        // Extract 15-char core
        if (result.is18Char) {
            result.id15 = id.substring(0, 15);
            String actualChecksum = id.substring(15, 18);
            String expectedChecksum = computeChecksum(result.id15);

            result.checksum = actualChecksum;
            result.expectedChecksum = expectedChecksum;
            result.checksumValid = actualChecksum.equals(expectedChecksum);
            result.id18 = id;
        } else {
            result.id15 = id;
            result.expectedChecksum = computeChecksum(result.id15);
            result.checksum = result.expectedChecksum;
            result.checksumValid = true;
            result.id18 = result.id15 + result.expectedChecksum;
        }

        // Parse components
        result.objectPrefix = result.id15.substring(0, 3);
        result.instanceId = result.id15.substring(3, 6);
        result.reserved = result.id15.substring(6, 7);
        result.recordNumberBase62 = result.id15.substring(7, 15);

        // Lookup object type
        result.objectType = OBJECT_PREFIXES.getOrDefault(result.objectPrefix, "Unknown");

        // Convert record number to decimal
        try {
            result.recordNumberDecimal = base62ToDecimal(result.recordNumberBase62);
        } catch (Exception e) {
            result.errorMessage = "Invalid Base62 record number: " + e.getMessage();
            return result;
        }

        result.valid = true;
        return result;
    }

    /**
     * Compute 3-character checksum for a 15-char Salesforce ID
     *
     * Algorithm:
     * 1. Split ID into 3 segments of 5 characters
     * 2. Reverse each segment
     * 3. For each segment, create 5-bit binary string (1=uppercase, 0=lowercase/digit)
     * 4. Convert 5-bit value to index (0-31)
     * 5. Map index to checksum character (A-Z, 0-5)
     */
    private static String computeChecksum(String id15) {
        if (id15.length() != 15) {
            throw new IllegalArgumentException("ID must be exactly 15 characters");
        }

        StringBuilder checksum = new StringBuilder();

        // Process 3 segments of 5 characters each
        for (int i = 0; i < 3; i++) {
            int start = i * 5;
            int end = start + 5;
            String segment = id15.substring(start, end);

            // Reverse the segment
            String reversed = new StringBuilder(segment).reverse().toString();

            // Build 5-bit binary string (1 for uppercase, 0 for lowercase/digit)
            StringBuilder bits = new StringBuilder();
            for (char c : reversed.toCharArray()) {
                bits.append(Character.isUpperCase(c) ? '1' : '0');
            }

            // Convert binary string to index (0-31)
            int index = Integer.parseInt(bits.toString(), 2);

            // Map to checksum character
            checksum.append(CHECKSUM_ALPHABET.charAt(index));
        }

        return checksum.toString();
    }

    /**
     * Convert Base62 string to decimal (long)
     */
    private static long base62ToDecimal(String base62) {
        long result = 0;
        for (char c : base62.toCharArray()) {
            int index = BASE62_ALPHABET.indexOf(c);
            if (index == -1) {
                throw new IllegalArgumentException("Invalid Base62 character: " + c);
            }
            result = result * BASE62 + index;
        }
        return result;
    }

    /**
     * Format a long number as plain string without separators
     */
    public static String formatNumber(long number) {
        return String.valueOf(number);
    }

    /**
     * Convert decimal (long) to Base62 string with minimum length padding
     */
    public static String decimalToBase62(long value, int minLength) {
        if (value < 0) {
            throw new IllegalArgumentException("Only non-negative values are supported");
        }

        if (value == 0) {
            String zeros = "0";
            while (zeros.length() < minLength) {
                zeros += "0";
            }
            return zeros;
        }

        StringBuilder result = new StringBuilder();
        long n = value;
        while (n > 0) {
            int remainder = (int) (n % BASE62);
            result.insert(0, BASE62_ALPHABET.charAt(remainder));
            n = n / BASE62;
        }

        // Pad with zeros to minimum length
        while (result.length() < minLength) {
            result.insert(0, '0');
        }

        return result.toString();
    }

    /**
     * Validate if a string is a valid Salesforce ID prefix (first 15 chars must be valid)
     * Checksum can be invalid - we only check the base 15 characters
     */
    public static boolean isValidSalesforceIdPrefix(String id) {
        if (id == null || id.length() < 15) {
            return false;
        }

        String id15 = id.substring(0, 15);
        return id15.matches("[A-Za-z0-9]{15}");
    }

    /**
     * Normalize a Salesforce ID to 15 characters (strip checksum if present)
     */
    public static String normalize15(String id) {
        if (id == null) {
            throw new IllegalArgumentException("ID cannot be null");
        }

        String trimmed = id.trim();
        if (trimmed.length() == 18) {
            return trimmed.substring(0, 15);
        } else if (trimmed.length() == 15) {
            return trimmed;
        } else {
            throw new IllegalArgumentException("ID must be 15 or 18 characters");
        }
    }

    /**
     * Convert a 15-char ID to 18-char by adding checksum
     */
    public static String computeId18(String id15) {
        if (id15.length() != 15) {
            throw new IllegalArgumentException("ID must be exactly 15 characters");
        }
        return id15 + computeChecksum(id15);
    }

    /**
     * Generate a sequence of Salesforce IDs starting from a base ID
     *
     * @param baseId Base Salesforce ID (15 or 18 chars)
     * @param count Number of IDs to generate
     * @param upward Direction: true=increment, false=decrement
     * @param use18Char Output format: true=18-char, false=15-char
     * @return List of generated Salesforce IDs
     */
    public static java.util.List<String> generateSequence(String baseId, int count,
                                                          boolean upward, boolean use18Char) {
        java.util.List<String> ids = new java.util.ArrayList<>();

        if (count <= 0) {
            return ids;
        }

        // Normalize to 15 chars
        String id15 = normalize15(baseId);

        // Extract prefix7 and record number
        String prefix7 = id15.substring(0, 7);
        String counter8 = id15.substring(7, 15);
        long startValue = base62ToDecimal(counter8);

        // Generate sequence
        int step = upward ? 1 : -1;
        long current = startValue;

        for (int i = 0; i < count; i++) {
            // Check bounds (same as sfidenum.py)
            if (current < 0 || current > MAX_BASE62_8) {
                break;
            }

            // Generate ID
            String base62 = decimalToBase62(current, 8);
            String newId15 = prefix7 + base62;

            if (use18Char) {
                ids.add(computeId18(newId15));
            } else {
                ids.add(newId15);
            }

            current += step;
        }

        return ids;
    }
}
