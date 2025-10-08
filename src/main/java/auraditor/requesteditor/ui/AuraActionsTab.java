/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.swing.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.fasterxml.jackson.core.JsonProcessingException;

import auraditor.core.ActionRequest;
import auraditor.core.AuraMessage;
import auraditor.core.AuraResponse;

public class AuraActionsTab implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private static final String AURA_DATAPARAM = "message";
    private static final String AURA_INDICATOR = "aura.token";
    private static final String AURA_RESPONSE_START = "while(1)";

    public JTabbedPane pane;
    public ByteArray content;
    private AuraMessage currentAuraMessage;

    private boolean editable;
    private boolean isEdited = false;
    private boolean isRequest;

    private MontoyaApi api;
    private HttpRequestResponse currentRequestResponse;
    
    // Track if we've already shown an error dialog for the current invalid JSON state
    private boolean errorDialogShown = false;

    public Map<String, ActionRequestPanel> actionRequestTabs = new HashMap<String, ActionRequestPanel>();
    public Map<String, ActionResponsePanel> actionResponseTabs = new HashMap<String, ActionResponsePanel>();

    public AuraActionsTab(EditorCreationContext creationContext, boolean isRequest, MontoyaApi api) {
        this.pane = new JTabbedPane();
        this.api = api;
        this.isRequest = isRequest;
        this.editable = isRequest;
        
        // Add right-click context menu for adding new actions
        setupTabContextMenu();
    }

    @Override
    public String caption() {
        return "Aura Actions";
    }

    @Override
    public Component uiComponent() {
        return this.pane;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (isRequest) {
            return isRequestEnabled(requestResponse.request());
        } else {
            return isResponseEnabled(requestResponse.response());
        }
    }

    /**
     * Return true if the content is a valid Aura request.
     * If the request is valid Aura, additionally parse it into an AuraMessage object.
     *
     * @param request An HTTP request
     * @return true if the content is a valid Aura request.
     */
    private boolean isRequestEnabled(HttpRequest request) {
        if (request == null)
            return false;

        boolean isAuraMessage = request.hasParameter(AURA_INDICATOR, HttpParameterType.BODY);

        if (request.httpService() != null) {
            boolean isAuraEndpoint = true; // true until proven wrong

            try {
                if (request.url() != null) {
                    isAuraEndpoint = request.path().contains("/aura");
                }
            } catch (Exception e) {
                // Handle malformed URL exception - assume it's not an Aura endpoint
                api.logging().logToError("Malformed URL in AuraActionsTab: " + e.getMessage());
                isAuraEndpoint = false;
            }

            if (isAuraEndpoint && isAuraMessage) {
                return true;
            }
        } else {
            return isAuraMessage;
        }
        return false;
    }

    private boolean isResponseEnabled(HttpResponse response) {
        if (response == null)
            return false;

        String mimeType = response.statedMimeType().toString();
        if (!"JSON".equals(mimeType)) {
            return false;
        }
        String body = response.bodyToString();
        return body.startsWith(AURA_RESPONSE_START);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentRequestResponse = requestResponse;
        // Reset error dialog flag for each new request
        errorDialogShown = false;
        
        if (requestResponse == null) {
            return;
        }
        
        if (isRequest) {
            requestSetup(requestResponse.request());
        } else {
            responseSetup(requestResponse.response());
        }
    }

    public void requestSetup(HttpRequest request) {
        if (request == null)
            return;

        this.cleanTab();

        // Try standard parameter extraction first
        HttpParameter param = request.parameter(AURA_DATAPARAM, HttpParameterType.BODY);
        String jsonText = null;

        if (param != null) {
            jsonText = Utils.urlDecode(param.value());
        } else {
            // Fallback: manually parse body for multiline parameter values
            jsonText = extractParameterFromBody(request.bodyToString(), AURA_DATAPARAM);
        }

        if (jsonText == null || jsonText.trim().isEmpty()) {
            return;
        }

        // Debug logging for multiline JSON issues
        if (jsonText.contains("\n") || jsonText.contains("\r")) {
            api.logging().logToOutput("AuraActionsTab: Processing multiline JSON with " +
                jsonText.split("\\r?\\n").length + " lines");
        }

        try {
            // Try parsing with improved multiline JSON handling
            String processedJson = preprocessJsonForParsing(jsonText);
            this.currentAuraMessage = new AuraMessage(processedJson, api);

            //create tabs for each aura action
            Iterator<String> iter = currentAuraMessage.actionMap.keySet().iterator();
            int tabIndex = 0;
            while (iter.hasNext()) {
                String nextId = iter.next();
                ActionRequest nextActionRequest = currentAuraMessage.actionMap.get(nextId);
                ActionRequestPanel arPanel = new ActionRequestPanel(nextActionRequest, editable, api);

                this.actionRequestTabs.put(nextId, arPanel);
                String tabTitle = nextId + "::" + nextActionRequest.calledMethod;
                this.pane.add(tabTitle, arPanel);
                
                // Add close button to all tabs
                addCloseButtonToTab(tabIndex, nextId);
                tabIndex++;
            }

        } catch (JsonProcessingException e) {
            // TODO: Fix beautified JSON parsing issues in "message" parameter
            // ISSUE: When users manually beautify JSON in the "message" parameter with proper formatting
            //        (newlines, indentation), Jackson fails to parse it with errors like:
            //        "Unexpected end-of-input: expected close marker for Object"
            // ROOT CAUSE: The JSON minification logic in AuraTab.java doesn't always handle
            //            complex multiline JSON structures correctly when they contain nested
            //            objects, arrays, or escaped characters within form parameters
            // IMPACT: Users cannot view/edit beautified JSON in Aura Actions tab
            // WORKAROUND: Users must manually minify JSON or use single-line format
            // FUTURE FIX: Implement robust multiline JSON detection and normalization that:
            //            1. Properly handles nested braces and brackets in strings
            //            2. Correctly processes escaped characters within JSON strings
            //            3. Preserves JSON structure while removing formatting whitespace
            //            4. Handles edge cases with mixed quote types and escaped sequences
            api.logging().logToError("JsonProcessingException in AuraActionsTab: " + e.getMessage());
            // Log the problematic JSON for debugging multiline issues
            if (jsonText.contains("\n") || jsonText.contains("\r")) {
                api.logging().logToError("Problematic multiline JSON (first 500 chars): " +
                    jsonText.substring(0, Math.min(500, jsonText.length())));
            }
        } catch (IOException e) {
            api.logging().logToError("IOException in AuraActionsTab: " + e.getMessage());
        }
    }

    public void responseSetup(HttpResponse response) {
        if (response == null)
            return;

        this.cleanTab();

        String body = response.bodyToString();
        AuraResponse auraResponse;
        try {
            auraResponse = new AuraResponse(body);
        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException in AuraActionsTab response: " + e.getMessage());

            // Invalid JSON.  happens when we do "key": function()
            // Jackson doesn't support parsing this, so we will just return the string then
            JTextArea textArea = new JTextArea(body);
            textArea.setEditable(false);
            // Enable line wrapping for better readability
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);
            this.pane.add("Invalid JSON", new JScrollPane(textArea));
            return;
        } catch (IOException e) {
            api.logging().logToError("IOException in AuraActionsTab response: " + e.getMessage());
            return;
        }
        Iterator<String> responseIter = auraResponse.responseActionMap.keySet().iterator();
        while (responseIter.hasNext()) {
            String nextActionId = responseIter.next();
            ActionResponsePanel nextPanel = new ActionResponsePanel(auraResponse.responseActionMap.get(nextActionId), api);
            this.pane.add(nextActionId, nextPanel);
        }
    }

    private void cleanTab() {
        pane.removeAll();
        pane.revalidate();
    }

    /**
     * Add a close button to the specified tab
     */
    private void addCloseButtonToTab(int tabIndex, String actionId) {
        // Create a panel for the tab title with close button
        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabPanel.setOpaque(false);
        
        // Get the current tab title
        String tabTitle = this.pane.getTitleAt(tabIndex);
        JLabel titleLabel = new JLabel(tabTitle);
        
        // Create close button
        JButton closeButton = new JButton("×");
        closeButton.setPreferredSize(new java.awt.Dimension(16, 16));
        closeButton.setMargin(new java.awt.Insets(0, 0, 0, 0));
        closeButton.setBorderPainted(false);
        closeButton.setContentAreaFilled(false);
        closeButton.setFocusable(false);
        closeButton.setToolTipText("Close this action");
        
        // Add close button action
        closeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                removeActionTab(actionId);
            }
        });
        
        tabPanel.add(titleLabel);
        tabPanel.add(Box.createHorizontalStrut(5)); // Small gap
        tabPanel.add(closeButton);
        
        // Set the custom tab component
        this.pane.setTabComponentAt(tabIndex, tabPanel);
    }

    /**
     * Remove an action tab and update the underlying data
     */
    private void removeActionTab(String actionId) {
        // Find the tab with this action ID
        ActionRequestPanel panelToRemove = actionRequestTabs.get(actionId);
        if (panelToRemove != null) {
            // Remove from the tab pane
            int tabIndex = this.pane.indexOfComponent(panelToRemove);
            if (tabIndex >= 0) {
                this.pane.removeTabAt(tabIndex);
            }

            // Remove from our tracking maps
            actionRequestTabs.remove(actionId);

            // Remove from the AuraMessage
            if (currentAuraMessage != null) {
                currentAuraMessage.actionMap.remove(actionId);
                currentAuraMessage.setEdited(true);

                // Check if this was the last action - if so, create empty JSON
                if (currentAuraMessage.actionMap.isEmpty()) {
                    createEmptyMessage();
                }
            }

            // Mark as edited
            isEdited = true;
        }
    }

    /**
     * Create an empty actions array when all actions are removed
     */
    private void createEmptyMessage() {
        try {
            // Create JSON object with empty actions array: {"actions":[]}
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.node.ObjectNode emptyNode = mapper.createObjectNode();
            com.fasterxml.jackson.databind.node.ArrayNode emptyActions = mapper.createArrayNode();
            emptyNode.set("actions", emptyActions);

            // Replace the current aura message with empty actions structure
            if (currentAuraMessage != null) {
                currentAuraMessage.auraMessage = emptyNode;
                currentAuraMessage.setEdited(true);
            }

            api.logging().logToOutput("All Aura actions removed - message parameter set to {\"actions\":[]}");

        } catch (Exception e) {
            api.logging().logToError("Error creating empty message: " + e.getMessage());
        }
    }

    /**
     * Setup right-click context menu for the tab pane
     */
    private void setupTabContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();
        
        JMenuItem addActionItem = new JMenuItem("Add New Action");
        addActionItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editable && currentAuraMessage != null) {
                    addNewActionTab();
                }
            }
        });
        
        contextMenu.add(addActionItem);
        
        // Add mouse listener to the tab pane
        this.pane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e, contextMenu);
            }
            
            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e, contextMenu);
            }
            
            private void maybeShowPopup(MouseEvent e, JPopupMenu popup) {
                if (e.isPopupTrigger() && editable && currentAuraMessage != null) {
                    popup.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    /**
     * Add a new action tab with default values
     */
    private void addNewActionTab() {
        if (currentAuraMessage == null) {
            return;
        }
        
        // Generate a unique ID for the new action
        String newActionId = generateUniqueActionId();
        
        // Create a new ActionRequest with default values
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode newActionNode = mapper.createObjectNode();
        
        newActionNode.put("id", newActionId);
        newActionNode.put("descriptor", "aura://CustomController/ACTION$customMethod");
        newActionNode.put("callingDescriptor", "UNKNOWN");
        newActionNode.set("params", mapper.createObjectNode());
        
        try {
            // Create the ActionRequest object
            auraditor.core.ActionRequest newActionRequest = new auraditor.core.ActionRequest(newActionNode, currentAuraMessage, api);
            
            // Add to the current message
            currentAuraMessage.actionMap.put(newActionId, newActionRequest);
            currentAuraMessage.setEdited(true);
            
            // Create the panel
            ActionRequestPanel arPanel = new ActionRequestPanel(newActionRequest, editable, api);
            actionRequestTabs.put(newActionId, arPanel);
            
            // Add the tab
            String tabTitle = newActionId + "::" + newActionRequest.calledMethod;
            this.pane.add(tabTitle, arPanel);
            
            // Add close button (new tabs can always be closed)
            int newTabIndex = this.pane.getTabCount() - 1;
            addCloseButtonToTab(newTabIndex, newActionId);
            
            // Select the new tab
            this.pane.setSelectedIndex(newTabIndex);
            
            // Mark as edited
            isEdited = true;
            
        } catch (Exception ex) {
            api.logging().logToError("Failed to create new action tab: " + ex.getMessage());
        }
    }

    /**
     * Extract parameter value from raw body when standard parameter parsing fails
     * This handles cases where multiline content breaks the parameter parser
     */
    private String extractParameterFromBody(String body, String paramName) {
        if (body == null || body.trim().isEmpty()) {
            return null;
        }

        // URL form encoded data: param1=value1&param2=value2
        // Look for paramName= in the body
        String searchPattern = paramName + "=";
        int startIndex = body.indexOf(searchPattern);

        if (startIndex == -1) {
            return null;
        }

        startIndex += searchPattern.length();

        // For multiline JSON parameters, we need to be more careful about finding the end
        // The standard approach of looking for '&' doesn't work well with complex JSON
        int endIndex = findParameterEnd(body, startIndex);

        String paramValue = body.substring(startIndex, endIndex);

        // URL decode the extracted value
        return Utils.urlDecode(paramValue);
    }

    /**
     * Find the end of a parameter value, handling multiline JSON content
     */
    private int findParameterEnd(String body, int startIndex) {
        // Look for common URL-encoded parameter separators
        int ampersandIndex = body.indexOf('&', startIndex);

        // If there's no & found, this is likely the last parameter
        if (ampersandIndex == -1) {
            return body.length();
        }

        // Check if we have a complex JSON structure by looking for common patterns
        String valuePrefix = body.substring(startIndex, Math.min(startIndex + 100, body.length()));

        // If it starts with encoded { (%7B) or raw {, it's likely JSON
        if (valuePrefix.startsWith("%7B") || valuePrefix.startsWith("{")) {
            // For JSON, we need to find the matching closing brace
            return findJsonParameterEnd(body, startIndex);
        }

        // For non-JSON parameters, use the standard & separator
        return ampersandIndex;
    }

    /**
     * Find the end of a JSON parameter by matching braces (accounting for URL encoding)
     */
    private int findJsonParameterEnd(String body, int startIndex) {
        int braceDepth = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = startIndex; i < body.length(); i++) {
            String current = body.substring(i, Math.min(i + 3, body.length()));

            if (escaped) {
                escaped = false;
                continue;
            }

            // Handle URL-encoded characters
            if (current.startsWith("%22")) { // URL-encoded quote "
                inString = !inString;
                i += 2; // Skip the encoded bytes
            } else if (current.startsWith("%5C")) { // URL-encoded backslash \
                escaped = true;
                i += 2;
            } else if (current.startsWith("%7B")) { // URL-encoded {
                if (!inString) braceDepth++;
                i += 2;
            } else if (current.startsWith("%7D")) { // URL-encoded }
                if (!inString) {
                    braceDepth--;
                    if (braceDepth == 0) {
                        return i + 3; // Return position after the closing brace
                    }
                }
                i += 2;
            } else if (current.charAt(0) == '"' && !inString) {
                inString = true;
            } else if (current.charAt(0) == '"' && inString) {
                inString = false;
            } else if (current.charAt(0) == '\\' && inString) {
                escaped = true;
            } else if (current.charAt(0) == '{' && !inString) {
                braceDepth++;
            } else if (current.charAt(0) == '}' && !inString) {
                braceDepth--;
                if (braceDepth == 0) {
                    return i + 1; // Return position after the closing brace
                }
            } else if (current.charAt(0) == '&' && braceDepth == 0 && !inString) {
                // Found the end of parameter
                return i;
            }
        }

        // If we reach here, no proper end was found, return end of string
        return body.length();
    }

    /**
     * Preprocess JSON text to handle multiline beautified JSON issues and escape control characters
     */
    private String preprocessJsonForParsing(String jsonText) {
        if (jsonText == null || jsonText.trim().isEmpty()) {
            return jsonText;
        }

        // Already handled basic normalization in Utils.urlDecode(), but add extra safety
        String processed = jsonText;

        // Handle common issues with multiline JSON in HTTP parameters
        // 1. Ensure proper line ending normalization
        processed = processed.replace("\r\n", "\n").replace("\r", "\n");

        // 2. Handle URL-encoded control characters and escape them properly for JSON
        // Replace %0A (URL-encoded newline) with escaped JSON newline
        processed = processed.replace("%0A", "\\n");
        processed = processed.replace("%0D", "\\r");
        processed = processed.replace("%09", "\\t");

        // 3. Escape any literal control characters that might be in the JSON
        // This handles cases where control chars are already decoded
        processed = escapeControlCharactersInJson(processed);

        // 4. Clean up any extra whitespace while preserving JSON structure
        processed = processed.trim();

        // 5. If JSON appears to be minified on one line but should be multiline,
        //    attempt to detect and fix formatting issues
        if (!processed.contains("\n") && processed.length() > 1000) {
            // Very long single-line JSON might be improperly formatted
            // Let Jackson parse and reformat it
            try {
                com.fasterxml.jackson.databind.ObjectMapper tempMapper =
                    new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode tempNode = tempMapper.readTree(processed);
                processed = tempMapper.writeValueAsString(tempNode);
            } catch (Exception e) {
                // If reformatting fails, use original
                api.logging().logToOutput("Could not reformat potential minified JSON, using original");
            }
        }

        return processed;
    }

    /**
     * Escape control characters within JSON string values
     * This handles literal control characters that appear in JSON strings
     */
    private String escapeControlCharactersInJson(String json) {
        if (json == null || json.isEmpty()) {
            return json;
        }

        StringBuilder result = new StringBuilder(json.length());
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            // Track if we're inside a string
            if (c == '"' && !escaped) {
                inString = !inString;
                result.append(c);
                continue;
            }

            // Track escape sequences
            if (c == '\\' && !escaped) {
                escaped = true;
                result.append(c);
                continue;
            }

            // If we're in a string and encounter a control character, escape it
            if (inString && !escaped) {
                if (c == '\n') {
                    result.append("\\n");
                    continue;
                } else if (c == '\r') {
                    result.append("\\r");
                    continue;
                } else if (c == '\t') {
                    result.append("\\t");
                    continue;
                } else if (c < 0x20) {
                    // Other control characters - escape as unicode
                    result.append(String.format("\\u%04x", (int) c));
                    continue;
                }
            }

            // Reset escaped flag
            if (escaped) {
                escaped = false;
            }

            result.append(c);
        }

        return result.toString();
    }

    /**
     * Generate a unique action ID that doesn't conflict with existing ones
     */
    private String generateUniqueActionId() {
        int counter = 1;
        String baseId = "new_action";
        String candidateId = baseId + "_" + counter;
        
        while (currentAuraMessage.actionMap.containsKey(candidateId)) {
            counter++;
            candidateId = baseId + "_" + counter;
        }
        
        return candidateId;
    }

    private void updateTabActions() {
        Iterator<String> actionIter = this.actionRequestTabs.keySet().iterator();
        boolean hasAnyErrors = false;
        
        while (actionIter.hasNext()) {
            ActionRequestPanel nextActionRequestTab = this.actionRequestTabs.get(actionIter.next());
            try {
                nextActionRequestTab.updateActionBurp();
            } catch (JsonProcessingException e) {
                hasAnyErrors = true;
                // Only show error dialog once per invalid JSON state
                if (!errorDialogShown) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this.pane,
                            "Invalid JSON detected in one of the Aura Actions.\n" +
                            "Please fix the JSON syntax to send the updated request.\n" +
                            "Using original payload for now.",
                            "JSON Syntax Error",
                            JOptionPane.WARNING_MESSAGE);
                    });
                    errorDialogShown = true;
                }
                api.logging().logToError("Invalid JSON entered, using original payload: " + e.getMessage());
            } catch (IOException e) {
                api.logging().logToError("IOException in Aura Actions tab: " + e.getMessage());
            }
        }
        
        // Reset error dialog flag if all JSON is now valid
        if (!hasAnyErrors) {
            errorDialogShown = false;
        }
    }

    @Override
    public HttpRequest getRequest() {
        if (currentRequestResponse == null || currentRequestResponse.request() == null) {
            return null;
        }

        // If nothing has been modified, return the original request
        if (!isModified()) {
            return currentRequestResponse.request();
        }

        // Update all the action panels to capture any edits
        updateTabActions();

        if (this.currentAuraMessage != null && this.currentAuraMessage.isEdited()) {
            isEdited = true;
        }

        String auraMessageStr;
        try {
            auraMessageStr = this.currentAuraMessage.getAuraRequest();
        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException in getRequest: " + e.getMessage());
            return currentRequestResponse.request();
        }

        String encodedMessage = Utils.urlEncode(auraMessageStr);
        return currentRequestResponse.request().withParameter(
            HttpParameter.bodyParameter(AURA_DATAPARAM, encodedMessage)
        );
    }

    @Override
    public HttpResponse getResponse() {
        if (currentRequestResponse == null || currentRequestResponse.response() == null) {
            return null;
        }
        return currentRequestResponse.response();
    }

    @Override
    public boolean isModified() {
        // Check if any ActionRequestPanel has been modified
        for (ActionRequestPanel panel : actionRequestTabs.values()) {
            if (panel.isMessageEdited()) {
                return true;
            }
        }
        
        // Also check if the AuraMessage itself has been edited
        return isEdited || (currentAuraMessage != null && currentAuraMessage.isEdited());
    }

    @Override
    public Selection selectedData() {
        if (pane.getSelectedIndex() == -1) {
            return null;
        } else {
            int actionIndex = pane.getSelectedIndex();
            ActionPanel activeComponent = (ActionPanel) pane.getComponentAt(actionIndex);
            byte[] selectedText = activeComponent.getSelectedText();
            if (selectedText != null) {
                return Selection.selection(ByteArray.byteArray(selectedText));
            }
            return null;
        }
    }
}
