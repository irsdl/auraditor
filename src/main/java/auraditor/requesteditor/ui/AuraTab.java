/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.awt.Component;
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

public class AuraTab implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

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

    public AuraTab(EditorCreationContext creationContext, boolean isRequest, MontoyaApi api) {
        this.pane = new JTabbedPane();
        this.api = api;
        this.isRequest = isRequest;
        this.editable = isRequest;
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
                api.logging().logToError("Malformed URL in AuraTab: " + e.getMessage());
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
            api.logging().logToOutput("AuraTab: Processing multiline JSON with " +
                jsonText.split("\\r?\\n").length + " lines");
        }

        try {
            // Apply CRLF preprocessing to handle multiline JSON properly
            String processedJson = preprocessJsonForParsing(jsonText);
            this.currentAuraMessage = new AuraMessage(processedJson, api);

            //create tabs for each aura action
            Iterator<String> iter = currentAuraMessage.actionMap.keySet().iterator();
            while (iter.hasNext()) {
                String nextId = iter.next();
                ActionRequest nextActionRequest = currentAuraMessage.actionMap.get(nextId);
                ActionRequestPanel arPanel = new ActionRequestPanel(nextActionRequest, editable, api);

                this.actionRequestTabs.put(nextId, arPanel);
                this.pane.add(nextId + "::" + nextActionRequest.calledMethod, arPanel);
            }

        } catch (JsonProcessingException e) {
            api.logging().logToError("JsonProcessingException in AuraTab: " + e.getMessage());
        } catch (IOException e) {
            api.logging().logToError("IOException in AuraTab: " + e.getMessage());
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
            api.logging().logToError("JsonProcessingException in AuraTab response: " + e.getMessage());

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
            api.logging().logToError("IOException in AuraTab response: " + e.getMessage());
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

        // Find the next & or end of string to determine parameter value end
        int endIndex = body.indexOf('&', startIndex);
        if (endIndex == -1) {
            endIndex = body.length();
        }

        String paramValue = body.substring(startIndex, endIndex);
        return Utils.urlDecode(paramValue);
    }

    /**
     * Preprocess JSON text to handle multiline beautified JSON issues
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

        // 2. Handle potential encoding artifacts
        processed = processed.replace("%0A", "\n").replace("%0D", "");

        // 3. Clean up any extra whitespace while preserving JSON structure
        processed = processed.trim();

        // 4. If JSON appears to be minified on one line but should be multiline,
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
}
