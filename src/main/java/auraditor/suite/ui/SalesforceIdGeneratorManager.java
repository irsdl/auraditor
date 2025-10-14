/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Manager for Salesforce ID payload generators
 *
 * Handles:
 * - CRUD operations for generators
 * - Registration/unregistration with Burp Intruder
 * - Name uniqueness validation
 * - Cleanup on extension unload
 */
public class SalesforceIdGeneratorManager {

    private final MontoyaApi api;
    private final List<SalesforceIdGenerator> generators;
    private final Map<String, SalesforceIdGeneratorProvider> registeredProviders;

    public SalesforceIdGeneratorManager(MontoyaApi api) {
        this.api = api;
        this.generators = new ArrayList<>();
        this.registeredProviders = new HashMap<>();
    }

    /**
     * Get all generators
     */
    public List<SalesforceIdGenerator> getGenerators() {
        return new ArrayList<>(generators);
    }

    /**
     * Add a new generator
     * @throws IllegalArgumentException if name is not unique
     */
    public void addGenerator(SalesforceIdGenerator generator) {
        validateUniqueName(generator.getName(), -1);

        // Validate configuration
        String error = generator.validate();
        if (error != null) {
            throw new IllegalArgumentException(error);
        }

        generators.add(generator);
        registerWithBurp(generator);

        api.logging().logToOutput("Added Salesforce ID generator: " + generator.getName());
    }

    /**
     * Update an existing generator at the given index
     * @throws IllegalArgumentException if name is not unique or invalid
     */
    public void updateGenerator(int index, SalesforceIdGenerator generator) {
        if (index < 0 || index >= generators.size()) {
            throw new IndexOutOfBoundsException("Invalid generator index: " + index);
        }

        validateUniqueName(generator.getName(), index);

        // Validate configuration
        String error = generator.validate();
        if (error != null) {
            throw new IllegalArgumentException(error);
        }

        // Unregister old generator
        SalesforceIdGenerator oldGenerator = generators.get(index);
        unregisterFromBurp(oldGenerator);

        // Update and register new
        generators.set(index, generator);
        registerWithBurp(generator);

        api.logging().logToOutput("Updated Salesforce ID generator: " + generator.getName());
    }

    /**
     * Delete a generator at the given index
     */
    public void deleteGenerator(int index) {
        if (index < 0 || index >= generators.size()) {
            throw new IndexOutOfBoundsException("Invalid generator index: " + index);
        }

        SalesforceIdGenerator generator = generators.get(index);
        unregisterFromBurp(generator);
        generators.remove(index);

        api.logging().logToOutput("Deleted Salesforce ID generator: " + generator.getName());
    }

    /**
     * Get generator at index
     */
    public SalesforceIdGenerator getGenerator(int index) {
        if (index < 0 || index >= generators.size()) {
            return null;
        }
        return generators.get(index);
    }

    /**
     * Get number of generators
     */
    public int getGeneratorCount() {
        return generators.size();
    }

    /**
     * Validate that a generator name is unique
     * @param name Name to validate
     * @param excludeIndex Index to exclude from check (-1 for none)
     * @throws IllegalArgumentException if name is not unique
     */
    private void validateUniqueName(String name, int excludeIndex) {
        for (int i = 0; i < generators.size(); i++) {
            if (i == excludeIndex) {
                continue;
            }

            if (generators.get(i).getName().equals(name)) {
                throw new IllegalArgumentException("Generator name must be unique: " + name);
            }
        }
    }

    /**
     * Register a generator with Burp Intruder
     */
    private void registerWithBurp(SalesforceIdGenerator generator) {
        SalesforceIdGeneratorProvider provider = new SalesforceIdGeneratorProvider(generator);
        api.intruder().registerPayloadGeneratorProvider(provider);
        registeredProviders.put(generator.getName(), provider);
    }

    /**
     * Unregister a generator from Burp Intruder
     */
    private void unregisterFromBurp(SalesforceIdGenerator generator) {
        // Note: Burp Montoya API doesn't provide an unregister method
        // The provider will simply stop being used after this point
        registeredProviders.remove(generator.getName());
    }

    /**
     * Cleanup all generators (called on extension unload)
     */
    public void cleanup() {
        api.logging().logToOutput("Cleaning up " + generators.size() + " Salesforce ID generators");
        generators.clear();
        registeredProviders.clear();
    }
}
