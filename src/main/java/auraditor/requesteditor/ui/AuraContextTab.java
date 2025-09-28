/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.awt.Component;

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

public class AuraContextTab implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    private static final String AURA_CONTEXT_PARAM = "aura.context";
    private static final String AURA_INDICATOR = "aura.token";
    private static final String AURA_RESPONSE_START = "while(1)";

    public JTabbedPane pane;
    public ByteArray content;
    private AuraContextPanel contextPanel;

    private boolean editable;
    private boolean isEdited = false;
    private boolean isRequest;

    private MontoyaApi api;
    private HttpRequestResponse currentRequestResponse;

    public AuraContextTab(EditorCreationContext creationContext, boolean isRequest, MontoyaApi api) {
        this.pane = new JTabbedPane();
        this.api = api;
        this.isRequest = isRequest;
        this.editable = isRequest;
    }

    @Override
    public String caption() {
        return "Aura Context";
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
                api.logging().logToError("Malformed URL in AuraContextTab: " + e.getMessage());
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
        HttpParameter contextParam = request.parameter(AURA_CONTEXT_PARAM, HttpParameterType.BODY);
        String contextJson = null;

        if (contextParam != null) {
            contextJson = Utils.urlDecode(contextParam.value());
        } else {
            // Fallback: manually parse body for multiline parameter values
            contextJson = extractParameterFromBody(request.bodyToString(), AURA_CONTEXT_PARAM);
        }

        if (contextJson == null || contextJson.trim().isEmpty()) {
            return;
        }

        // Debug logging for multiline JSON issues
        if (contextJson.contains("\n") || contextJson.contains("\r")) {
            api.logging().logToOutput("AuraContextTab: Processing multiline aura.context JSON with " +
                contextJson.split("\\r?\\n").length + " lines");
        }

        try {
            // Create context panel for editing context directly with the JSON
            contextPanel = new AuraContextPanel(contextJson, editable, api);
            this.pane.add("Context", contextPanel);

        } catch (Exception e) {
            // TODO: Fix beautified JSON parsing issues in "aura.context" parameter
            // ISSUE: When users manually beautify JSON in the "aura.context" parameter with proper formatting
            //        (newlines, indentation), the parsing logic fails with JsonProcessingException
            // ROOT CAUSE: Similar to AuraActionsTab, the JSON normalization logic doesn't handle
            //            complex multiline JSON structures correctly when they contain:
            //            - Nested objects and arrays with formatting
            //            - Mixed quote types and escaped characters
            //            - Complex parameter encoding within form data
            // IMPACT: Users cannot view/edit beautified aura.context JSON in Context tab
            // WORKAROUND: Users must manually minify JSON or use single-line format
            // FUTURE FIX: Implement same robust JSON normalization as mentioned in AuraActionsTab:
            //            1. Enhanced multiline JSON detection and cleanup
            //            2. Proper handling of URL-encoded parameters with complex JSON values
            //            3. Better form parameter parsing for multiline content
            //            4. Unified JSON processing across all Aura editor tabs
            api.logging().logToError("Exception in AuraContextTab requestSetup: " + e.getMessage());
            // Log the problematic JSON for debugging multiline issues
            if (contextJson.contains("\n") || contextJson.contains("\r")) {
                api.logging().logToError("Problematic multiline aura.context JSON (first 500 chars): " +
                    contextJson.substring(0, Math.min(500, contextJson.length())));
            }
        }
    }

    public void responseSetup(HttpResponse response) {
        if (response == null)
            return;

        this.cleanTab();

        String body = response.bodyToString();
        // For responses, we just show the context info if available
        JTextArea textArea = new JTextArea("Context information is only available for Aura requests.\n\nResponse Body:\n" + body);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        this.pane.add("Response", new JScrollPane(textArea));
    }

    private void cleanTab() {
        pane.removeAll();
        pane.revalidate();
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
     * Normalize JSON for transmission by removing unnecessary whitespace and line breaks
     * that could cause issues when URL-encoded in HTTP parameters
     */
    private String normalizeJsonForTransmission(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                return "{}";
            }
            
            // Parse the JSON to validate it and remove formatting
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode node = mapper.readTree(json);
            
            // Write as compact JSON without pretty printing
            return mapper.writeValueAsString(node);
        } catch (Exception e) {
            api.logging().logToError("Error normalizing JSON for transmission: " + e.getMessage());
            // If parsing fails, at least normalize line endings
            return json.replace("\r\n", "").replace("\r", "").replace("\n", "");
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

        // Get the edited context from the context panel
        if (contextPanel != null && contextPanel.isMessageEdited()) {
            try {
                String editedContextJson = contextPanel.textEditor.getText();
                
                // Normalize line endings to prevent CRLF issues
                // Remove platform-specific line endings and convert to compact JSON
                String normalizedJson = normalizeJsonForTransmission(editedContextJson);
                String encodedContext = Utils.urlEncode(normalizedJson);
                
                // Return the request with updated aura.context parameter
                return currentRequestResponse.request().withParameter(
                    HttpParameter.bodyParameter(AURA_CONTEXT_PARAM, encodedContext)
                );
            } catch (Exception e) {
                api.logging().logToError("Exception in getRequest while updating context: " + e.getMessage());
                return currentRequestResponse.request();
            }
        }

        return currentRequestResponse.request();
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
        // Check if the context panel has been modified
        if (contextPanel != null && contextPanel.isMessageEdited()) {
            return true;
        }
        
        // Check if we've marked this tab as edited
        return isEdited;
    }

    @Override
    public Selection selectedData() {
        if (pane.getSelectedIndex() == -1 || contextPanel == null) {
            return null;
        } else {
            byte[] selectedText = contextPanel.getSelectedText();
            if (selectedText != null) {
                return Selection.selection(ByteArray.byteArray(selectedText));
            }
            return null;
        }
    }
}
