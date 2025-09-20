/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Utility class for detecting Aura/Lightning framework requests
 * Shared logic for determining if a request is suitable for Auraditor analysis
 */
public class AuraDetector {
    
    private static final String AURA_TOKEN_PARAM = "aura.token";
    private static final String AURA_CONTEXT_PARAM = "aura.context";
    
    /**
     * Determines if a request contains Aura framework parameters
     * suitable for Auraditor analysis
     * 
     * @param requestResponse The HTTP request/response pair to check
     * @return true if the request contains aura.token and aura.context parameters
     */
    public static boolean isAuraRequest(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        
        return isAuraRequest(requestResponse.request());
    }
    
    /**
     * Determines if a request contains Aura framework parameters
     * suitable for Auraditor analysis
     * 
     * @param request The HTTP request to check
     * @return true if the request contains aura.token and aura.context parameters
     */
    public static boolean isAuraRequest(HttpRequest request) {
        if (request == null) {
            return false;
        }
        
        // Check for both aura.token and aura.context parameters in the request body
        boolean hasAuraToken = request.hasParameter(AURA_TOKEN_PARAM, HttpParameterType.BODY);
        boolean hasAuraContext = request.hasParameter(AURA_CONTEXT_PARAM, HttpParameterType.BODY);
        
        // Also check if the URL path contains /aura for additional validation
        boolean isAuraEndpoint = false;
        try {
            if (request.url() != null) {
                isAuraEndpoint = request.path().contains("/aura");
            }
        } catch (Exception e) {
            // Handle malformed URL - assume it's not an Aura endpoint
            isAuraEndpoint = false;
        }
        
        // Return true if we have both required parameters and it's an Aura endpoint
        return hasAuraToken && hasAuraContext && isAuraEndpoint;
    }
}
