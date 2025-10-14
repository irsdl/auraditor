/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.io.File;
import java.io.FileWriter;
import java.util.List;

/**
 * UI panel for managing Salesforce ID payload generators
 *
 * Provides interface for creating, editing, deleting, and exporting generators
 * that can be used with Burp Intruder.
 */
public class SalesforceIdPayloadGeneratorsPanel {

    private final MontoyaApi api;
    private final SalesforceIdGeneratorManager manager;
    private final JPanel mainPanel;

    // Left panel - generator list
    private final DefaultListModel<SalesforceIdGenerator> listModel;
    private final JList<SalesforceIdGenerator> generatorList;

    // Right panel - configuration form
    private final JTextField nameField;
    private final JRadioButton useBaseIdRadio;
    private final JRadioButton useIntruderRadio;
    private final JTextField baseIdField;
    private final JSpinner countSpinner;
    private final JRadioButton upwardRadio;
    private final JRadioButton downwardRadio;
    private final JCheckBox use18CharCheckbox;
    private final JButton saveButton;
    private final JLabel statusLabel;

    private boolean updatingUI = false;
    private int selectedIndex = -1;
    private SwingWorker<Void, Integer> currentOutputWorker = null;
    private File lastUsedDirectory = null;

    public SalesforceIdPayloadGeneratorsPanel(MontoyaApi api, SalesforceIdGeneratorManager manager) {
        this.api = api;
        this.manager = manager;

        // Initialize UI components
        this.listModel = new DefaultListModel<>();
        this.generatorList = new JList<>(listModel);

        this.nameField = new JTextField(20);
        this.useBaseIdRadio = new JRadioButton("Use Base ID:", true);
        this.useIntruderRadio = new JRadioButton("Use Intruder Payload");
        this.baseIdField = new JTextField(20);
        this.countSpinner = new JSpinner(new SpinnerNumberModel(100, 1, 999999999, 10));
        this.upwardRadio = new JRadioButton("Upward", true);
        this.downwardRadio = new JRadioButton("Downward");
        this.use18CharCheckbox = new JCheckBox("Output 18-character IDs (default is 15-char)");
        this.saveButton = new JButton("Save");
        this.statusLabel = new JLabel(" ");

        // Create main panel
        this.mainPanel = new JPanel(new BorderLayout(10, 10));
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        createUI();
        loadGenerators();
    }

    private void createUI() {
        // Top toolbar
        JPanel toolbarPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JButton newButton = new JButton("New Generator");
        JButton deleteButton = new JButton("Delete");
        JButton outputButton = new JButton("Output to File");
        JButton exportConfigsButton = new JButton("Export Configs");
        JButton importConfigsButton = new JButton("Import Configs");

        newButton.addActionListener(e -> createNewGenerator());
        deleteButton.addActionListener(e -> deleteSelectedGenerator());
        outputButton.addActionListener(e -> outputToFile());
        exportConfigsButton.addActionListener(e -> exportConfigs());
        importConfigsButton.addActionListener(e -> importConfigs());

        toolbarPanel.add(newButton);
        toolbarPanel.add(deleteButton);
        toolbarPanel.add(outputButton);
        toolbarPanel.add(exportConfigsButton);
        toolbarPanel.add(importConfigsButton);

        mainPanel.add(toolbarPanel, BorderLayout.NORTH);

        // Split pane for list and configuration
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(createListPanel());
        splitPane.setRightComponent(createConfigPanel());
        splitPane.setDividerLocation(200);

        mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    private JPanel createListPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Generators"));

        generatorList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        generatorList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedGenerator();
            }
        });

        JScrollPane scrollPane = new JScrollPane(generatorList);
        scrollPane.setPreferredSize(new Dimension(200, 400));

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Generator Configuration"));

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;

        // Name
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        formPanel.add(new JLabel("Name:"), gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 2;
        formPanel.add(nameField, gbc);
        row++;

        // Separator
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        formPanel.add(Box.createVerticalStrut(10), gbc);
        row++;

        // Base ID source radio buttons
        ButtonGroup sourceGroup = new ButtonGroup();
        sourceGroup.add(useBaseIdRadio);
        sourceGroup.add(useIntruderRadio);

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        formPanel.add(useBaseIdRadio, gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 2;
        formPanel.add(baseIdField, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        formPanel.add(useIntruderRadio, gbc);
        row++;

        // Separator
        gbc.gridx = 0;
        gbc.gridy = row;
        formPanel.add(Box.createVerticalStrut(10), gbc);
        row++;

        // Count and direction
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        formPanel.add(new JLabel("Count:"), gbc);

        gbc.gridx = 1;
        formPanel.add(countSpinner, gbc);

        gbc.gridx = 2;
        JPanel directionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        ButtonGroup directionGroup = new ButtonGroup();
        directionGroup.add(upwardRadio);
        directionGroup.add(downwardRadio);
        directionPanel.add(upwardRadio);
        directionPanel.add(downwardRadio);
        formPanel.add(directionPanel, gbc);
        row++;

        // Separator
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        formPanel.add(Box.createVerticalStrut(10), gbc);
        row++;

        // Output format
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        formPanel.add(use18CharCheckbox, gbc);
        row++;

        // Separator
        gbc.gridx = 0;
        gbc.gridy = row;
        formPanel.add(Box.createVerticalStrut(15), gbc);
        row++;

        // Save button and status
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        saveButton.setVisible(false);
        formPanel.add(saveButton, gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 2;
        statusLabel.setForeground(Color.RED);
        formPanel.add(statusLabel, gbc);

        panel.add(formPanel, BorderLayout.NORTH);

        // Add listeners for auto-save and validation
        setupFormListeners();

        return panel;
    }

    private void setupFormListeners() {
        DocumentListener docListener = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { onFieldChanged(); }
            public void removeUpdate(DocumentEvent e) { onFieldChanged(); }
            public void changedUpdate(DocumentEvent e) { onFieldChanged(); }
        };

        nameField.getDocument().addDocumentListener(docListener);
        baseIdField.getDocument().addDocumentListener(docListener);

        useBaseIdRadio.addActionListener(e -> {
            baseIdField.setEnabled(true);
            onFieldChanged();
        });

        useIntruderRadio.addActionListener(e -> {
            baseIdField.setEnabled(false);
            onFieldChanged();
        });

        countSpinner.addChangeListener(e -> onFieldChanged());
        upwardRadio.addActionListener(e -> onFieldChanged());
        downwardRadio.addActionListener(e -> onFieldChanged());
        use18CharCheckbox.addActionListener(e -> onFieldChanged());

        saveButton.addActionListener(e -> saveCurrentGenerator());
    }

    private void onFieldChanged() {
        if (updatingUI || selectedIndex < 0) {
            return;
        }

        // Get current values
        SalesforceIdGenerator current = getCurrentFormValues();

        // Validate
        String error = current.validate();

        if (error != null) {
            // Invalid - show save button and error
            saveButton.setVisible(true);
            statusLabel.setText(error);
        } else {
            // Valid - auto-save
            try {
                manager.updateGenerator(selectedIndex, current);
                saveButton.setVisible(false);
                statusLabel.setText(" ");

                // Update list display
                listModel.set(selectedIndex, current);
            } catch (Exception ex) {
                // Error saving (e.g., duplicate name)
                saveButton.setVisible(true);
                statusLabel.setText(ex.getMessage());
            }
        }
    }

    private SalesforceIdGenerator getCurrentFormValues() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            name = "Unnamed";
        }

        SalesforceIdGenerator gen = new SalesforceIdGenerator(name);
        gen.setBaseId(baseIdField.getText().trim());
        gen.setUseIntruderPayload(useIntruderRadio.isSelected());
        gen.setCount((Integer) countSpinner.getValue());
        gen.setUpward(upwardRadio.isSelected());
        gen.setGenerate18Char(use18CharCheckbox.isSelected());

        return gen;
    }

    private void loadGenerators() {
        listModel.clear();
        for (SalesforceIdGenerator gen : manager.getGenerators()) {
            listModel.addElement(gen);
        }
    }

    private void loadSelectedGenerator() {
        selectedIndex = generatorList.getSelectedIndex();

        if (selectedIndex < 0) {
            clearForm();
            return;
        }

        updatingUI = true;

        SalesforceIdGenerator gen = manager.getGenerator(selectedIndex);
        if (gen != null) {
            nameField.setText(gen.getName());
            baseIdField.setText(gen.getBaseId());
            useBaseIdRadio.setSelected(!gen.isUseIntruderPayload());
            useIntruderRadio.setSelected(gen.isUseIntruderPayload());
            baseIdField.setEnabled(!gen.isUseIntruderPayload());
            countSpinner.setValue(gen.getCount());
            upwardRadio.setSelected(gen.isUpward());
            downwardRadio.setSelected(!gen.isUpward());
            use18CharCheckbox.setSelected(gen.isGenerate18Char());

            saveButton.setVisible(false);
            statusLabel.setText(" ");
        }

        updatingUI = false;
    }

    private void clearForm() {
        updatingUI = true;

        nameField.setText("");
        baseIdField.setText("");
        useBaseIdRadio.setSelected(true);
        useIntruderRadio.setSelected(false);
        baseIdField.setEnabled(true);
        countSpinner.setValue(100);
        upwardRadio.setSelected(true);
        downwardRadio.setSelected(false);
        use18CharCheckbox.setSelected(false);

        saveButton.setVisible(false);
        statusLabel.setText(" ");

        updatingUI = false;
    }

    private void createNewGenerator() {
        int counter = manager.getGeneratorCount() + 1;
        String name = "Generator" + counter;

        // Ensure unique name
        while (true) {
            boolean unique = true;
            for (SalesforceIdGenerator gen : manager.getGenerators()) {
                if (gen.getName().equals(name)) {
                    unique = false;
                    counter++;
                    name = "Generator" + counter;
                    break;
                }
            }
            if (unique) break;
        }

        SalesforceIdGenerator newGen = new SalesforceIdGenerator(name);
        newGen.setBaseId("001000000000000"); // Default example ID

        try {
            manager.addGenerator(newGen);
            listModel.addElement(newGen);
            generatorList.setSelectedIndex(listModel.getSize() - 1);
        } catch (Exception e) {
            api.logging().logToError("Error creating generator: " + e.getMessage());
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    private void deleteSelectedGenerator() {
        if (selectedIndex < 0) {
            return;
        }

        // Use Swing's built-in confirmation dialog with proper parent
        int result = JOptionPane.showConfirmDialog(
                SwingUtilities.getWindowAncestor(mainPanel),
                "Delete generator '" + manager.getGenerator(selectedIndex).getName() + "'?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            try {
                manager.deleteGenerator(selectedIndex);
                listModel.remove(selectedIndex);
                clearForm();
            } catch (Exception e) {
                api.logging().logToError("Error deleting generator: " + e.getMessage());
                statusLabel.setText("Error: " + e.getMessage());
            }
        }
    }

    private void saveCurrentGenerator() {
        if (selectedIndex < 0) {
            return;
        }

        SalesforceIdGenerator gen = getCurrentFormValues();
        String error = gen.validate();

        if (error != null) {
            api.logging().logToError("Validation error: " + error);
            statusLabel.setText(error);
            return;
        }

        try {
            manager.updateGenerator(selectedIndex, gen);
            listModel.set(selectedIndex, gen);
            saveButton.setVisible(false);
            statusLabel.setText(" ");
        } catch (Exception e) {
            api.logging().logToError("Error saving generator: " + e.getMessage());
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    private void outputToFile() {
        if (selectedIndex < 0) {
            api.logging().logToOutput("Output: No generator selected");
            statusLabel.setText("Please select a generator first");
            return;
        }

        SalesforceIdGenerator gen = manager.getGenerator(selectedIndex);
        if (!gen.canExportToFile()) {
            api.logging().logToOutput("Output: Generator requires Base ID");
            statusLabel.setText("Can only output generators with a Base ID");
            return;
        }

        // Show file chooser with proper parent
        JFileChooser fileChooser = new JFileChooser();
        if (lastUsedDirectory != null) {
            fileChooser.setCurrentDirectory(lastUsedDirectory);
        }
        fileChooser.setDialogTitle("Output Salesforce IDs to File");
        fileChooser.setSelectedFile(new File(
            lastUsedDirectory != null ? lastUsedDirectory : new File("."),
            "salesforce-ids-" + gen.getName() + ".txt"
        ));

        int result = fileChooser.showSaveDialog(SwingUtilities.getWindowAncestor(mainPanel));
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        lastUsedDirectory = file.getParentFile();

        // Create cancel button
        JButton cancelButton = new JButton("Cancel Output");
        cancelButton.addActionListener(e -> {
            if (currentOutputWorker != null && !currentOutputWorker.isDone()) {
                currentOutputWorker.cancel(true);
                statusLabel.setText("Cancelling...");
            }
        });

        // Show cancel button in status area temporarily
        Container statusParent = statusLabel.getParent();
        statusParent.add(cancelButton);
        statusParent.revalidate();
        statusParent.repaint();

        // Generate and output in background with streaming and progress
        currentOutputWorker = new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() throws Exception {
                // Normalize to 15 chars
                String id15 = SalesforceIdAnalyzer.normalize15(gen.getBaseId());

                // Extract prefix7 and record number
                String prefix7 = id15.substring(0, 7);
                String counter8 = id15.substring(7, 15);
                long startValue = base62ToDecimal(counter8);

                // Generate sequence with streaming (no memory buildup)
                int step = gen.isUpward() ? 1 : -1;
                long current = startValue;

                try (FileWriter writer = new FileWriter(file)) {
                    for (int i = 0; i < gen.getCount(); i++) {
                        // Check cancellation
                        if (isCancelled()) {
                            break;
                        }

                        // Check bounds
                        if (current < 0 || current > SalesforceIdAnalyzer.MAX_BASE62_8) {
                            break;
                        }

                        // Generate single ID
                        String base62 = decimalToBase62(current, 8);
                        String newId15 = prefix7 + base62;

                        String idToWrite;
                        if (gen.isGenerate18Char()) {
                            idToWrite = SalesforceIdAnalyzer.computeId18(newId15);
                        } else {
                            idToWrite = newId15;
                        }

                        writer.write(idToWrite + "\n");

                        current += step;

                        // Publish progress every 1000 IDs
                        if (i % 1000 == 0 || i == gen.getCount() - 1) {
                            publish(i + 1);
                        }
                    }
                }

                return null;
            }

            @Override
            protected void process(List<Integer> chunks) {
                // Update UI with latest progress
                Integer progress = chunks.get(chunks.size() - 1);
                int percentage = (int) ((progress * 100.0) / gen.getCount());
                statusLabel.setText(String.format("Outputting: %,d / %,d (%d%%)",
                        progress, gen.getCount(), percentage));
            }

            @Override
            protected void done() {
                // Remove cancel button
                statusParent.remove(cancelButton);
                statusParent.revalidate();
                statusParent.repaint();

                try {
                    if (isCancelled()) {
                        api.logging().logToOutput("Output cancelled by user");
                        statusLabel.setText("Output cancelled");
                    } else {
                        get();
                        api.logging().logToOutput("Output " + gen.getCount() + " IDs to: " + file.getAbsolutePath());
                        statusLabel.setText(String.format("Output %,d IDs successfully", gen.getCount()));
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error outputting: " + e.getMessage());
                    statusLabel.setText("Output failed: " + e.getMessage());
                }

                currentOutputWorker = null;
            }
        };

        currentOutputWorker.execute();
    }

    /**
     * Convert Base62 string to decimal (long) - helper for streaming generation
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
     * Convert decimal to Base62 string with padding - helper for streaming generation
     */
    private String decimalToBase62(long value, int minLength) {
        String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        if (value < 0) {
            throw new IllegalArgumentException("Only non-negative values are supported");
        }

        if (value == 0) {
            return "0".repeat(Math.max(0, minLength));
        }

        StringBuilder result = new StringBuilder();
        long n = value;
        while (n > 0) {
            int remainder = (int) (n % 62);
            result.insert(0, alphabet.charAt(remainder));
            n = n / 62;
        }

        // Pad with zeros to minimum length
        while (result.length() < minLength) {
            result.insert(0, '0');
        }

        return result.toString();
    }

    private void exportConfigs() {
        // Show file chooser with proper parent
        JFileChooser fileChooser = new JFileChooser();
        if (lastUsedDirectory != null) {
            fileChooser.setCurrentDirectory(lastUsedDirectory);
        }
        fileChooser.setDialogTitle("Export Generator Configurations");
        fileChooser.setSelectedFile(new File(
            lastUsedDirectory != null ? lastUsedDirectory : new File("."),
            "salesforce-id-generators.json"
        ));

        int result = fileChooser.showSaveDialog(SwingUtilities.getWindowAncestor(mainPanel));
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        lastUsedDirectory = file.getParentFile();

        try {
            manager.exportToFile(file);
            api.logging().logToOutput("Exported configurations to: " + file.getAbsolutePath());
            statusLabel.setText("Configurations exported successfully");
        } catch (Exception e) {
            api.logging().logToError("Error exporting configurations: " + e.getMessage());
            statusLabel.setText("Export failed: " + e.getMessage());
        }
    }

    private void importConfigs() {
        // Show file chooser with proper parent
        JFileChooser fileChooser = new JFileChooser();
        if (lastUsedDirectory != null) {
            fileChooser.setCurrentDirectory(lastUsedDirectory);
        }
        fileChooser.setDialogTitle("Import Generator Configurations");

        int result = fileChooser.showOpenDialog(SwingUtilities.getWindowAncestor(mainPanel));
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        lastUsedDirectory = file.getParentFile();

        try {
            manager.importFromFile(file);
            loadGenerators();
            api.logging().logToOutput("Imported configurations from: " + file.getAbsolutePath());
            statusLabel.setText("Configurations imported successfully");
        } catch (Exception e) {
            api.logging().logToError("Error importing configurations: " + e.getMessage());
            statusLabel.setText("Import failed: " + e.getMessage());
        }
    }

    public JComponent getComponent() {
        return mainPanel;
    }
}
