/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;

import java.util.Iterator;
import java.util.List;

/**
 * Burp Intruder payload generator for Salesforce IDs
 *
 * Generates sequences of Salesforce IDs based on a configuration.
 * Can use either a predefined base ID or the current Intruder payload as the base.
 */
public class SalesforceIdPayloadGenerator implements PayloadGenerator {

    private final SalesforceIdGenerator config;
    private Iterator<String> payloadIterator;
    private String resolvedBaseId;
    private boolean initialized;

    public SalesforceIdPayloadGenerator(SalesforceIdGenerator config) {
        this.config = config;
        this.payloadIterator = null;
        this.resolvedBaseId = null;
        this.initialized = false;
    }

    @Override
    public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint) {
        // Initialize on first call
        if (!initialized) {
            initialized = true;

            try {
                // Resolve base ID based on configuration
                if (config.isUseIntruderPayload()) {
                    // Use current Intruder payload as base
                    String baseValue = insertionPoint.baseValue().toString();

                    // Validate that it's a valid Salesforce ID (first 15 chars)
                    if (!SalesforceIdAnalyzer.isValidSalesforceIdPrefix(baseValue)) {
                        // Invalid ID - return empty sequence
                        return GeneratedPayload.end();
                    }

                    resolvedBaseId = baseValue;
                } else {
                    // Use configured base ID
                    resolvedBaseId = config.getBaseId();

                    // Should already be validated, but double-check
                    if (resolvedBaseId == null || resolvedBaseId.trim().isEmpty()) {
                        return GeneratedPayload.end();
                    }
                }

                // Generate sequence using SalesforceIdAnalyzer
                List<String> payloads = SalesforceIdAnalyzer.generateSequence(
                    resolvedBaseId,
                    config.getCount(),
                    config.isUpward(),
                    config.isGenerate18Char()
                );

                // Create iterator
                payloadIterator = payloads.iterator();

            } catch (Exception e) {
                // Any error during initialization - return empty sequence
                return GeneratedPayload.end();
            }
        }

        // Return next payload or end
        if (payloadIterator != null && payloadIterator.hasNext()) {
            return GeneratedPayload.payload(payloadIterator.next());
        } else {
            return GeneratedPayload.end();
        }
    }
}
