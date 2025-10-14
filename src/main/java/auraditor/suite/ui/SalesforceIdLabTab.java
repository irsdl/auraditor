/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;

/**
 * Tab for Salesforce ID utilities with multiple sub-tabs
 *
 * Sub-tabs:
 * - ID Analysis: Analyze 15/18 character Salesforce IDs
 * - Payload Generators: Manage Burp Intruder payload generators
 *
 * Reference: https://codebycody.com/salesforce-ids-explained/
 */
public class SalesforceIdLabTab {

    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final JTabbedPane tabbedPane;
    private final SalesforceIdGeneratorManager generatorManager;

    public SalesforceIdLabTab(MontoyaApi api, SalesforceIdGeneratorManager generatorManager) {
        this.api = api;
        this.generatorManager = generatorManager;
        this.mainPanel = new JPanel(new BorderLayout());

        // Create tabbed pane for sub-tabs
        this.tabbedPane = new JTabbedPane();

        // Add ID Analysis sub-tab
        SalesforceIdAnalysisPanel idAnalysisPanel = new SalesforceIdAnalysisPanel(api);
        this.tabbedPane.addTab("ID Analysis", idAnalysisPanel.getComponent());

        // Add Payload Generators sub-tab
        SalesforceIdPayloadGeneratorsPanel payloadGeneratorsPanel =
            new SalesforceIdPayloadGeneratorsPanel(api, generatorManager);
        this.tabbedPane.addTab("Payload Generators", payloadGeneratorsPanel.getComponent());

        this.mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Get the main UI component for this tab
     */
    public JComponent getComponent() {
        return mainPanel;
    }
}

/**
 * Panel for analyzing Salesforce IDs (15 or 18 character format)
 *
 * Features:
 * - Validates ID length (15 or 18 characters)
 * - Computes and validates 18-char checksum
 * - Displays object prefix, instance ID, and record number
 * - Converts record number from Base62 to decimal
 * - Identifies common object types from prefix
 */
class SalesforceIdAnalysisPanel {

    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final JTextField idTextField;
    private final JButton analyzeButton;
    private final JTextArea resultsArea;

    public SalesforceIdAnalysisPanel(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new JPanel(new BorderLayout(10, 10));
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Create input panel
        JPanel inputPanel = createInputPanel();
        this.mainPanel.add(inputPanel, BorderLayout.NORTH);

        // Create results area
        this.resultsArea = new JTextArea();
        this.resultsArea.setEditable(false);
        this.resultsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
        this.resultsArea.setLineWrap(false);
        this.resultsArea.setWrapStyleWord(false);

        // Set initial help text
        showHelpText();

        JScrollPane scrollPane = new JScrollPane(resultsArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(600, 400));

        this.mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Wire up button action
        this.idTextField = (JTextField) inputPanel.getComponent(1);
        this.analyzeButton = (JButton) inputPanel.getComponent(2);
        this.analyzeButton.addActionListener(e -> performAnalysis());

        // Allow Enter key in text field to trigger analysis
        this.idTextField.addActionListener(e -> performAnalysis());
    }

    /**
     * Create the input panel with text field and analyze button
     */
    private JPanel createInputPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JLabel label = new JLabel("Salesforce ID:");
        label.setFont(new Font(label.getFont().getName(), Font.BOLD, 14));
        panel.add(label);

        JTextField textField = new JTextField(25);
        textField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
        panel.add(textField);

        JButton button = new JButton("Analyze");
        button.setFont(new Font(button.getFont().getName(), Font.BOLD, 14));
        panel.add(button);

        return panel;
    }

    /**
     * Show initial help text
     */
    private void showHelpText() {
        resultsArea.setText(
            "Salesforce ID Lab - Analyze 15 or 18 character Salesforce IDs\n" +
            "================================================================\n\n" +
            "Enter a Salesforce ID above and click 'Analyze' to see:\n\n" +
            "  • ID validation (15 or 18 characters)\n" +
            "  • 18-character format with checksum\n" +
            "  • Checksum validation (for 18-char IDs)\n" +
            "  • Object type identification\n" +
            "  • Instance ID\n" +
            "  • Record number (Base62 and decimal)\n\n" +
            "Examples:\n" +
            "  15-char: 001Vc00000PHoN1\n" +
            "  18-char: 001Vc00000PHoN1IAL\n\n" +
            "Reference: https://codebycody.com/salesforce-ids-explained/"
        );
    }

    /**
     * Get the main UI component for this panel
     */
    public JComponent getComponent() {
        return mainPanel;
    }

    /**
     * Perform analysis when button is clicked
     */
    private void performAnalysis() {
        String input = idTextField.getText();

        if (input == null || input.trim().isEmpty()) {
            showHelpText();
            return;
        }

        // Analyze the ID
        SalesforceIdAnalyzer.AnalysisResult result = SalesforceIdAnalyzer.analyze(input);

        // Display results
        displayResults(result);

        // Log to Burp
        if (result.valid) {
            api.logging().logToOutput("Analyzed Salesforce ID: " + input + " -> " + result.objectType);
        } else {
            api.logging().logToOutput("Invalid Salesforce ID: " + input + " -> " + result.errorMessage);
        }
    }

    /**
     * Display analysis results in the text area
     */
    private void displayResults(SalesforceIdAnalyzer.AnalysisResult result) {
        StringBuilder output = new StringBuilder();
        output.append("Salesforce ID Analysis\n");
        output.append("======================\n\n");

        if (!result.valid) {
            output.append("✗ INVALID SALESFORCE ID\n");
            output.append("✗ ").append(result.errorMessage).append("\n");
            resultsArea.setText(output.toString());
            return;
        }

        // Valid ID - show results
        if (result.is18Char) {
            output.append("✓ Valid 18-character Salesforce ID\n");
            if (result.checksumValid) {
                output.append("✓ Checksum is valid (").append(result.checksum).append(")\n");
            } else {
                output.append("✗ Checksum is INVALID\n");
                output.append("   Expected checksum: ").append(result.expectedChecksum).append("\n");
                output.append("   Provided checksum: ").append(result.checksum).append("\n");
            }
            output.append("\n");
            output.append("Base 15-character ID:\n");
            output.append("  ").append(result.id15).append("\n");
        } else {
            output.append("✓ Valid 15-character Salesforce ID\n");
            output.append("\n");
            output.append("Complete 18-character ID:\n");
            output.append("  ").append(result.id18).append("\n");
            output.append("\n");
            output.append("Checksum: ").append(result.checksum).append("\n");
        }

        output.append("\n");
        output.append("ID Components:\n");
        output.append("--------------\n");
        output.append("Object Prefix:  ").append(result.objectPrefix);
        if (!"Unknown".equals(result.objectType)) {
            output.append(" (").append(result.objectType).append(")");
        } else {
            output.append(" (Unknown Object Type)");
        }
        output.append("\n");
        output.append("Instance ID:    ").append(result.instanceId).append("\n");
        output.append("Reserved:       ").append(result.reserved).append("\n");
        output.append("\n");
        output.append("Record Number:\n");
        output.append("  Base62:       ").append(result.recordNumberBase62).append("\n");
        output.append("  Decimal:      ").append(SalesforceIdAnalyzer.formatNumber(result.recordNumberDecimal)).append("\n");

        // Show corrected ID if checksum was invalid
        if (result.is18Char && !result.checksumValid) {
            output.append("\n");
            output.append("Corrected 18-character ID:\n");
            output.append("  ").append(result.id15).append(result.expectedChecksum).append("\n");
        }

        resultsArea.setText(output.toString());
    }
}
