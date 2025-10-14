/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;

/**
 * Provider factory for Salesforce ID payload generators
 *
 * Creates instances of SalesforceIdPayloadGenerator for Burp Intruder.
 * Each provider is registered with Burp and appears in the Intruder UI
 * with the name "Auraditor-{generatorName}".
 */
public class SalesforceIdGeneratorProvider implements PayloadGeneratorProvider {

    private final SalesforceIdGenerator config;

    public SalesforceIdGeneratorProvider(SalesforceIdGenerator config) {
        this.config = config;
    }

    @Override
    public String displayName() {
        return "Auraditor-" + config.getName();
    }

    @Override
    public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
        return new SalesforceIdPayloadGenerator(config);
    }
}
