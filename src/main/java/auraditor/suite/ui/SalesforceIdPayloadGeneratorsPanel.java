/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
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
        this.countSpinner = new JSpinner(new SpinnerNumberModel(100, 1, 1000000, 10));
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
        JButton exportButton = new JButton("Export to File");

        newButton.addActionListener(e -> createNewGenerator());
        deleteButton.addActionListener(e -> deleteSelectedGenerator());
        exportButton.addActionListener(e -> exportToFile());

        toolbarPanel.add(newButton);
        toolbarPanel.add(deleteButton);
        toolbarPanel.add(exportButton);

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
            JOptionPane.showMessageDialog(mainPanel, "Error creating generator: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void deleteSelectedGenerator() {
        if (selectedIndex < 0) {
            return;
        }

        int result = JOptionPane.showConfirmDialog(mainPanel,
                "Delete generator '" + manager.getGenerator(selectedIndex).getName() + "'?",
                "Confirm Delete", JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            try {
                manager.deleteGenerator(selectedIndex);
                listModel.remove(selectedIndex);
                clearForm();
            } catch (Exception e) {
                JOptionPane.showMessageDialog(mainPanel, "Error deleting generator: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
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
            JOptionPane.showMessageDialog(mainPanel, error, "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            manager.updateGenerator(selectedIndex, gen);
            listModel.set(selectedIndex, gen);
            saveButton.setVisible(false);
            statusLabel.setText(" ");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel, "Error saving: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportToFile() {
        if (selectedIndex < 0) {
            JOptionPane.showMessageDialog(mainPanel, "Please select a generator first",
                    "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        SalesforceIdGenerator gen = manager.getGenerator(selectedIndex);
        if (!gen.canExportToFile()) {
            JOptionPane.showMessageDialog(mainPanel,
                    "Can only export generators with a Base ID (not using Intruder Payload)",
                    "Cannot Export", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show file chooser
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Salesforce IDs to File");
        fileChooser.setSelectedFile(new File("salesforce-ids-" + gen.getName() + ".txt"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();

        // Generate and export in background
        SwingWorker<Void, Integer> worker = new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() throws Exception {
                List<String> ids = SalesforceIdAnalyzer.generateSequence(
                        gen.getBaseId(),
                        gen.getCount(),
                        gen.isUpward(),
                        gen.isGenerate18Char()
                );

                try (FileWriter writer = new FileWriter(file)) {
                    for (String id : ids) {
                        writer.write(id + "\n");
                    }
                }

                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    JOptionPane.showMessageDialog(mainPanel,
                            "Exported " + gen.getCount() + " IDs to:\n" + file.getAbsolutePath(),
                            "Export Successful", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(mainPanel,
                            "Error exporting: " + e.getMessage(),
                            "Export Failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        worker.execute();
    }

    public JComponent getComponent() {
        return mainPanel;
    }
}
