/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

/**
 * Configuration model for a Salesforce ID payload generator
 *
 * Represents a single generator that can be registered with Burp Intruder
 * to generate sequences of Salesforce IDs for testing.
 */
public class SalesforceIdGenerator {

    private String name;
    private String baseId; // Optional - base Salesforce ID (15 or 18 chars)
    private boolean useIntruderPayload; // If true, use current Intruder payload as base
    private int count; // Number of IDs to generate
    private boolean upward; // Direction: true=upward, false=downward
    private boolean generate18Char; // Output format: true=18-char, false=15-char (default)
    private String outputFilePath; // Optional file path for batch export
    private boolean modified; // Dirty flag for unsaved changes

    /**
     * Create a new generator with default settings
     */
    public SalesforceIdGenerator(String name) {
        this.name = name;
        this.baseId = "";
        this.useIntruderPayload = false;
        this.count = 100;
        this.upward = true;
        this.generate18Char = false;
        this.outputFilePath = "";
        this.modified = false;
    }

    /**
     * Copy constructor for cloning
     */
    public SalesforceIdGenerator(SalesforceIdGenerator other) {
        this.name = other.name;
        this.baseId = other.baseId;
        this.useIntruderPayload = other.useIntruderPayload;
        this.count = other.count;
        this.upward = other.upward;
        this.generate18Char = other.generate18Char;
        this.outputFilePath = other.outputFilePath;
        this.modified = other.modified;
    }

    // Getters and Setters

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (!this.name.equals(name)) {
            this.name = name;
            this.modified = true;
        }
    }

    public String getBaseId() {
        return baseId;
    }

    public void setBaseId(String baseId) {
        if (!this.baseId.equals(baseId)) {
            this.baseId = baseId;
            this.modified = true;
        }
    }

    public boolean isUseIntruderPayload() {
        return useIntruderPayload;
    }

    public void setUseIntruderPayload(boolean useIntruderPayload) {
        if (this.useIntruderPayload != useIntruderPayload) {
            this.useIntruderPayload = useIntruderPayload;
            this.modified = true;
        }
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        if (this.count != count) {
            this.count = count;
            this.modified = true;
        }
    }

    public boolean isUpward() {
        return upward;
    }

    public void setUpward(boolean upward) {
        if (this.upward != upward) {
            this.upward = upward;
            this.modified = true;
        }
    }

    public boolean isGenerate18Char() {
        return generate18Char;
    }

    public void setGenerate18Char(boolean generate18Char) {
        if (this.generate18Char != generate18Char) {
            this.generate18Char = generate18Char;
            this.modified = true;
        }
    }

    public String getOutputFilePath() {
        return outputFilePath;
    }

    public void setOutputFilePath(String outputFilePath) {
        if (!this.outputFilePath.equals(outputFilePath)) {
            this.outputFilePath = outputFilePath;
            this.modified = true;
        }
    }

    public boolean isModified() {
        return modified;
    }

    public void setModified(boolean modified) {
        this.modified = modified;
    }

    public void clearModified() {
        this.modified = false;
    }

    /**
     * Validate the generator configuration
     * @return null if valid, error message if invalid
     */
    public String validate() {
        if (name == null || name.trim().isEmpty()) {
            return "Name cannot be empty";
        }

        if (count <= 0) {
            return "Count must be positive";
        }

        if (count > 1000000) {
            return "Count cannot exceed 1,000,000";
        }

        // If using base ID, validate it
        if (!useIntruderPayload && (baseId == null || baseId.trim().isEmpty())) {
            return "Base ID is required when not using Intruder payload";
        }

        if (!useIntruderPayload && baseId != null && !baseId.trim().isEmpty()) {
            if (!SalesforceIdAnalyzer.isValidSalesforceIdPrefix(baseId.trim())) {
                return "Base ID must be a valid 15 or 18 character Salesforce ID";
            }

            // Validate that the record number doesn't exceed max bounds
            try {
                String id15 = SalesforceIdAnalyzer.normalize15(baseId.trim());
                String counter8 = id15.substring(7, 15);
                long recordValue = base62ToDecimal(counter8);

                if (recordValue < 0 || recordValue > SalesforceIdAnalyzer.MAX_BASE62_8) {
                    return "Base ID record number is out of bounds (0 to " +
                           SalesforceIdAnalyzer.MAX_BASE62_8 + ")";
                }
            } catch (Exception e) {
                return "Invalid Base ID format: " + e.getMessage();
            }
        }

        return null; // Valid
    }

    /**
     * Convert Base62 string to decimal (for validation)
     */
    private long base62ToDecimal(String base62) {
        String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        long result = 0;
        for (char c : base62.toCharArray()) {
            int index = alphabet.indexOf(c);
            if (index == -1) {
                throw new IllegalArgumentException("Invalid Base62 character: " + c);
            }
            result = result * 62 + index;
        }
        return result;
    }

    /**
     * Check if this generator can export to file
     * (only when base ID is set, not when using Intruder payload)
     */
    public boolean canExportToFile() {
        return !useIntruderPayload && baseId != null && !baseId.trim().isEmpty();
    }

    @Override
    public String toString() {
        return name;
    }
}
