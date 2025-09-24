/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.io.IOException;

import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JLabel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import auraditor.core.ActionRequest;

@SuppressWarnings("serial")
public class ActionRequestPanel extends ActionPanel {

    public boolean isEdited = false;
    public String paramStr;
    private ActionRequest actionRequest;
    private ObjectMapper mapper = new ObjectMapper();
    public JTextField controllerField;  // Made public for access from AuraTab
    public JTextField methodField;      // Made public for access from AuraTab
    public JTextField idField;          // Made public for access from AuraTab
    private boolean editable = true;
    private MontoyaApi api;
    
    // Error state tracking to prevent repeated error dialogs
    private boolean hasJsonError = false;
    private String lastErrorText = null;

    public ActionRequestPanel(ActionRequest ar, MontoyaApi api) {
        this(ar, true, api);
    }

    public ActionRequestPanel(ActionRequest ar, boolean editable, MontoyaApi api) {
        super(api);
        this.actionRequest = ar;
        this.api = api;
        JsonNode params = ar.getParams();
        this.editable = editable;
        String pretty = getPrettyPrintedParams(params);
        BorderLayout panelLayout = new BorderLayout();
        panelLayout.setVgap(5);

        this.setLayout(panelLayout);
        JPanel headerPanel = getHeaderPanel(ar);
        this.add(headerPanel, BorderLayout.PAGE_START);
        createBurpTextPane(pretty);

        // Add the appropriate component based on editor type
        if (this.textEditor instanceof ActionPanel.HttpRequestEditorWrapper) {
            this.add(((ActionPanel.HttpRequestEditorWrapper) this.textEditor).getComponent());
        } else {
            this.add(new javax.swing.JScrollPane(this.textEditor));
        }
    }

    public String getPrettyPrintedParams(JsonNode params) {
        String pretty;
        try {
            pretty = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(params);
        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException: " + e.getMessage());
            pretty = e.getMessage();
        }
        return pretty;
    }

    private void createBurpTextPane(String paramText) {
        this.textEditor.setText(paramText);
        this.textEditor.setEditable(editable);
        
        // Add document listener to track changes
        if (editable) {
            this.textEditor.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    ActionRequestPanel.this.resetErrorState();
                }
                
                @Override
                public void removeUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    ActionRequestPanel.this.resetErrorState();
                }
                
                @Override
                public void changedUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    ActionRequestPanel.this.resetErrorState();
                }
            });
        }
    }

    public ActionRequest getActionRequest() {
        return this.actionRequest;
    }

    public boolean isMessageEdited() {
        return isEdited; // Simple flag-based approach for now
    }

    public void updateActionBurp() throws JsonProcessingException, IOException {
        if (isEdited) {
            String modifiedText = textEditor.getText();
            
            // Check if this is the same text that previously had an error
            if (hasJsonError && modifiedText.equals(lastErrorText)) {
                // Don't try to parse again if it's the same invalid JSON
                return;
            }
            
            try {
                JsonNode newParamJson = mapper.readTree(modifiedText);
                this.actionRequest.updateParams((ObjectNode) newParamJson);
                // Clear error state on successful parsing
                hasJsonError = false;
                lastErrorText = null;
            } catch (JsonProcessingException e) {
                // Mark this text as having an error to avoid repeated parsing
                hasJsonError = true;
                lastErrorText = modifiedText;
                throw e; // Re-throw to maintain existing error handling
            }
        }
        if (!this.actionRequest.id.equals(this.idField.getText())) {
            this.actionRequest.updateId(this.idField.getText());
        }
        if (!this.actionRequest.calledController.equals(this.controllerField.getText())) {
            this.actionRequest.updateController(this.controllerField.getText());
        }
        if (!this.actionRequest.calledMethod.equals(this.methodField.getText())) {
            this.actionRequest.updateMethod(this.methodField.getText());
        }
    }

    @Deprecated
    public void updateAction() throws JsonProcessingException, IOException {
        if (isEdited) {
            JsonNode newParamJson = mapper.readTree(this.paramStr);
            this.actionRequest.updateParams((ObjectNode) newParamJson);
        }
    }

    private void resetErrorState() {
        hasJsonError = false;
        lastErrorText = null;
    }

    private JPanel getHeaderPanel(ActionRequest ar) {
        JPanel headerPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        // ID field (smaller, before Controller)
        JLabel idLabel = new JLabel("ID");
        this.idField = new JTextField(ar.id, 8); // Smaller text field
        this.idField.setEditable(editable);
        
        // Add document listener to track changes for ID field
        if (editable) {
            this.idField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void removeUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void changedUpdate(DocumentEvent e) {
                    isEdited = true;
                }
            });
        }

        JLabel controllerLabel = new JLabel("Controller");
        this.controllerField = new JTextField(ar.calledController);
        this.controllerField.setEditable(editable);
        
        // Add document listener to track changes for JTextField
        if (editable) {
            this.controllerField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void removeUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void changedUpdate(DocumentEvent e) {
                    isEdited = true;
                }
            });
        }

        JLabel methodLabel = new JLabel("Method");
        this.methodField = new JTextField(ar.calledMethod, 20);
        this.methodField.setEditable(editable);
        
        // Add document listener to track changes for JTextField
        if (editable) {
            this.methodField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void removeUpdate(DocumentEvent e) {
                    isEdited = true;
                }
                
                @Override
                public void changedUpdate(DocumentEvent e) {
                    isEdited = true;
                }
            });
        }

        // Adding ID label to grid
        gbc.gridx = 0; // Column 0
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(2, 2, 2, 2); // Add some padding
        headerPanel.add(idLabel, gbc);

        // Adding ID field to grid (smaller)
        gbc.gridx = 1; // Column 1
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE; // Don't expand horizontally
        gbc.weightx = 0.0;
        headerPanel.add(idField, gbc);

        // Adding Controller label to grid
        gbc.gridx = 2; // Column 2
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(2, 10, 2, 2); // Extra left margin for spacing
        headerPanel.add(controllerLabel, gbc);

        // Adding Controller field to grid
        gbc.gridx = 3; // Column 3
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 2, 2, 2); // Reset insets
        headerPanel.add(controllerField, gbc);

        // Adding Method label to grid
        gbc.gridx = 4; // Column 4
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        headerPanel.add(methodLabel, gbc);

        // Adding Method field to grid
        gbc.gridx = 5; // Column 5
        gbc.gridy = 0; // Row 0
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        headerPanel.add(this.methodField, gbc);

        return headerPanel;
    }
}
