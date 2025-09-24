/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.io.IOException;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import auraditor.core.AuraMessage;

@SuppressWarnings("serial")
public class AuraContextPanel extends ActionPanel {

    public boolean isEdited = false;
    private AuraMessage auraMessage;
    private ObjectMapper mapper = new ObjectMapper();
    private boolean editable = true;
    private MontoyaApi api;
    
    // Error state tracking to prevent repeated error dialogs
    private boolean hasJsonError = false;
    private String lastErrorText = null;

    public AuraContextPanel(AuraMessage auraMessage, MontoyaApi api) {
        this(auraMessage, true, api);
    }

    public AuraContextPanel(AuraMessage auraMessage, boolean editable, MontoyaApi api) {
        super(api);
        this.auraMessage = auraMessage;
        this.api = api;
        this.editable = editable;
        
        String contextJson = getContextJson();
        BorderLayout panelLayout = new BorderLayout();
        panelLayout.setVgap(5);

        this.setLayout(panelLayout);
        createBurpTextPane(contextJson);

        // Add the appropriate component based on editor type
        if (this.textEditor instanceof ActionPanel.HttpRequestEditorWrapper) {
            this.add(((ActionPanel.HttpRequestEditorWrapper) this.textEditor).getComponent());
        } else {
            this.add(new javax.swing.JScrollPane(this.textEditor));
        }
    }

    /**
     * Constructor for raw context JSON (from aura.context parameter)
     */
    public AuraContextPanel(String contextJson, boolean editable, MontoyaApi api) {
        super(api);
        this.auraMessage = null; // No AuraMessage since we're working with raw context
        this.api = api;
        this.editable = editable;
        
        BorderLayout panelLayout = new BorderLayout();
        panelLayout.setVgap(5);

        this.setLayout(panelLayout);
        createBurpTextPane(formatContextJson(contextJson));

        // Add the appropriate component based on editor type
        if (this.textEditor instanceof ActionPanel.HttpRequestEditorWrapper) {
            this.add(((ActionPanel.HttpRequestEditorWrapper) this.textEditor).getComponent());
        } else {
            this.add(new javax.swing.JScrollPane(this.textEditor));
        }
    }

    /**
     * Extract context (non-actions) from the Aura message
     */
    public String getContextJson() {
        try {
            if (auraMessage == null || auraMessage.auraMessage == null) {
                return "{}";
            }
            
            // Create a copy of the aura message without actions
            ObjectNode contextMessage = auraMessage.auraMessage.deepCopy();
            contextMessage.remove("actions");
            
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(contextMessage);
        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException in AuraContextPanel: " + e.getMessage());
            return "{}";
        } catch (Exception e) {
            api.logging().logToError("Unexpected exception in AuraContextPanel: " + e.getMessage());
            return "{}";
        }
    }

    /**
     * Format raw context JSON for display
     */
    private String formatContextJson(String contextJson) {
        try {
            if (contextJson == null || contextJson.trim().isEmpty()) {
                return "{}";
            }
            
            // Normalize line endings and trim whitespace to handle CRLF issues
            String normalizedJson = contextJson.replace("\r\n", "\n").replace("\r", "\n").trim();
            
            // Parse and pretty print the JSON
            JsonNode contextNode = mapper.readTree(normalizedJson);
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(contextNode);
        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException in formatContextJson: " + e.getMessage());
            api.logging().logToError("Original JSON: " + contextJson);
            // Return the original string if it can't be parsed, but normalize line endings
            return contextJson.replace("\r\n", "\n").replace("\r", "\n");
        } catch (Exception e) {
            api.logging().logToError("Unexpected exception in formatContextJson: " + e.getMessage());
            return contextJson.replace("\r\n", "\n").replace("\r", "\n");
        }
    }

    private void createBurpTextPane(String contextText) {
        this.textEditor.setText(contextText);
        this.textEditor.setEditable(editable);
        
        // Add document listener to track changes
        if (editable) {
            this.textEditor.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    AuraContextPanel.this.resetErrorState();
                }
                
                @Override
                public void removeUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    AuraContextPanel.this.resetErrorState();
                }
                
                @Override
                public void changedUpdate(DocumentEvent e) {
                    isEdited = true;
                    // Reset error state when text changes
                    AuraContextPanel.this.resetErrorState();
                }
            });
        }
    }

    public boolean isMessageEdited() {
        return isEdited;
    }

    public void updateAuraContext() throws JsonProcessingException, IOException {
        if (isEdited) {
            String modifiedText = textEditor.getText();
            
            // Check if this is the same text that previously had an error
            if (hasJsonError && modifiedText.equals(lastErrorText)) {
                // Don't try to parse again if it's the same invalid JSON
                return;
            }
            
            try {
                JsonNode newContextJson = mapper.readTree(modifiedText);
                
                if (newContextJson.isObject()) {
                    ObjectNode newContext = (ObjectNode) newContextJson;
                    
                    // Update the aura message with new context, but preserve actions
                    ArrayNode existingActions = (ArrayNode) auraMessage.auraMessage.get("actions");
                    
                    // Replace the aura message with new context
                    auraMessage.auraMessage = newContext;
                    
                    // Restore the actions
                    if (existingActions != null) {
                        auraMessage.auraMessage.set("actions", existingActions);
                    }
                    
                    // Mark as edited
                    auraMessage.setEdited(true);
                    
                    // Clear error state on successful parsing
                    hasJsonError = false;
                    lastErrorText = null;
                } else {
                    throw new JsonProcessingException("Context must be a JSON object") {};
                }
            } catch (JsonProcessingException e) {
                // Mark this text as having an error to avoid repeated parsing
                hasJsonError = true;
                lastErrorText = modifiedText;
                throw e; // Re-throw to maintain existing error handling
            }
        }
    }

    /**
     * Update context with raw JSON text, even if it's malformed.
     * This allows sending requests with invalid JSON if the user chooses to.
     */
    public void updateAuraContextWithRawJSON(String rawJsonText) {
        try {
            // First try to parse as valid JSON
            JsonNode parsedContext = mapper.readTree(rawJsonText);
            if (parsedContext.isObject()) {
                ObjectNode newContext = (ObjectNode) parsedContext;
                
                // Preserve existing actions
                ArrayNode existingActions = (ArrayNode) auraMessage.auraMessage.get("actions");
                auraMessage.auraMessage = newContext;
                if (existingActions != null) {
                    auraMessage.auraMessage.set("actions", existingActions);
                }
                auraMessage.setEdited(true);
            } else {
                // If it's not an object, wrap it in a simple structure
                ObjectNode wrapper = mapper.createObjectNode();
                wrapper.set("rawContext", parsedContext);
                
                // Preserve existing actions
                ArrayNode existingActions = (ArrayNode) auraMessage.auraMessage.get("actions");
                auraMessage.auraMessage = wrapper;
                if (existingActions != null) {
                    auraMessage.auraMessage.set("actions", existingActions);
                }
                auraMessage.setEdited(true);
            }
        } catch (JsonProcessingException e) {
            // If JSON parsing fails, create a text node with the raw content
            ObjectNode rawWrapper = mapper.createObjectNode();
            rawWrapper.put("invalidContextJSON", rawJsonText);
            
            // Preserve existing actions
            ArrayNode existingActions = (ArrayNode) auraMessage.auraMessage.get("actions");
            auraMessage.auraMessage = rawWrapper;
            if (existingActions != null) {
                auraMessage.auraMessage.set("actions", existingActions);
            }
            auraMessage.setEdited(true);
            
            api.logging().logToError("Using raw context JSON due to parse error: " + e.getMessage());
        }
    }

    private void resetErrorState() {
        hasJsonError = false;
        lastErrorText = null;
    }
}
