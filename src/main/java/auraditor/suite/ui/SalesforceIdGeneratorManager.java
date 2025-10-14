/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
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

    private static final String PERSISTENCE_KEY = "salesforce_id_generators";
    private final MontoyaApi api;
    private final List<SalesforceIdGenerator> generators;
    private final Map<String, Registration> registrations;
    private final ObjectMapper objectMapper;

    public SalesforceIdGeneratorManager(MontoyaApi api) {
        this.api = api;
        this.generators = new ArrayList<>();
        this.registrations = new HashMap<>();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

        // Load saved generators from project file
        loadFromPersistence();
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
        saveToPersistence();

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
        saveToPersistence();

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
        saveToPersistence();

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
        Registration registration = api.intruder().registerPayloadGeneratorProvider(provider);
        registrations.put(generator.getName(), registration);
    }

    /**
     * Unregister a generator from Burp Intruder
     */
    private void unregisterFromBurp(SalesforceIdGenerator generator) {
        Registration registration = registrations.remove(generator.getName());
        if (registration != null && registration.isRegistered()) {
            registration.deregister();
        }
    }

    /**
     * Cleanup all generators (called on extension unload)
     */
    public void cleanup() {
        // Save to persistence before cleanup
        saveToPersistence();

        api.logging().logToOutput("Cleaning up " + generators.size() + " Salesforce ID generators");

        // Deregister all providers
        for (Registration registration : registrations.values()) {
            if (registration.isRegistered()) {
                registration.deregister();
            }
        }

        generators.clear();
        registrations.clear();
    }

    /**
     * Export all generator configurations to a JSON file
     */
    public void exportToFile(File file) throws IOException {
        List<GeneratorConfig> configs = new ArrayList<>();
        for (SalesforceIdGenerator gen : generators) {
            configs.add(new GeneratorConfig(gen));
        }
        objectMapper.writeValue(file, configs);
    }

    /**
     * Import generator configurations from a JSON file
     */
    public void importFromFile(File file) throws IOException {
        GeneratorConfig[] configs = objectMapper.readValue(file, GeneratorConfig[].class);

        // Clear existing generators
        for (SalesforceIdGenerator gen : new ArrayList<>(generators)) {
            unregisterFromBurp(gen);
        }
        generators.clear();

        // Add imported generators
        for (GeneratorConfig config : configs) {
            SalesforceIdGenerator gen = config.toGenerator();
            generators.add(gen);
            registerWithBurp(gen);
        }

        // Save to persistence
        saveToPersistence();

        api.logging().logToOutput("Imported " + configs.length + " generator(s) from file");
    }

    /**
     * Save all generators to Burp project persistence
     */
    private void saveToPersistence() {
        try {
            PersistedObject persistedObject = api.persistence().extensionData();

            List<GeneratorConfig> configs = new ArrayList<>();
            for (SalesforceIdGenerator gen : generators) {
                configs.add(new GeneratorConfig(gen));
            }

            String json = objectMapper.writeValueAsString(configs);
            persistedObject.setString(PERSISTENCE_KEY, json);

            api.logging().logToOutput("Saved " + generators.size() + " generator(s) to project file");
        } catch (Exception e) {
            api.logging().logToError("Failed to save generators to persistence: " + e.getMessage());
        }
    }

    /**
     * Load generators from Burp project persistence
     */
    private void loadFromPersistence() {
        try {
            PersistedObject persistedObject = api.persistence().extensionData();
            String json = persistedObject.getString(PERSISTENCE_KEY);

            if (json != null && !json.isEmpty()) {
                GeneratorConfig[] configs = objectMapper.readValue(json, GeneratorConfig[].class);

                for (GeneratorConfig config : configs) {
                    SalesforceIdGenerator gen = config.toGenerator();
                    generators.add(gen);
                    registerWithBurp(gen);
                }

                api.logging().logToOutput("Loaded " + generators.size() + " generator(s) from project file");
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load generators from persistence: " + e.getMessage());
        }
    }

    /**
     * Internal class for JSON serialization/deserialization
     */
    private static class GeneratorConfig {
        public String name;
        public String baseId;
        public boolean useIntruderPayload;
        public int count;
        public boolean upward;
        public boolean generate18Char;

        // Default constructor for Jackson
        public GeneratorConfig() {
        }

        // Constructor from SalesforceIdGenerator
        public GeneratorConfig(SalesforceIdGenerator gen) {
            this.name = gen.getName();
            this.baseId = gen.getBaseId();
            this.useIntruderPayload = gen.isUseIntruderPayload();
            this.count = gen.getCount();
            this.upward = gen.isUpward();
            this.generate18Char = gen.isGenerate18Char();
        }

        // Convert to SalesforceIdGenerator
        public SalesforceIdGenerator toGenerator() {
            SalesforceIdGenerator gen = new SalesforceIdGenerator(name);
            gen.setBaseId(baseId);
            gen.setUseIntruderPayload(useIntruderPayload);
            gen.setCount(count);
            gen.setUpward(upward);
            gen.setGenerate18Char(generate18Char);
            return gen;
        }
    }
}
