/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Represents a base request stored in Auraditor for analysis
 */
public class BaseRequest {
    private static int nextId = 1;
    
    private final int id;
    private final String url;
    private String notes;
    private final HttpRequestResponse requestResponse;
    
    public BaseRequest(HttpRequestResponse requestResponse) {
        this.id = nextId++;
        this.requestResponse = requestResponse;
        this.url = requestResponse.request().url();
        this.notes = "";
    }
    
    public BaseRequest(HttpRequestResponse requestResponse, String notes) {
        this.id = nextId++;
        this.requestResponse = requestResponse;
        this.url = requestResponse.request().url();
        this.notes = notes != null ? notes : "";
    }
    
    public int getId() {
        return id;
    }
    
    public String getUrl() {
        return url;
    }
    
    public String getNotes() {
        return notes;
    }
    
    public void setNotes(String notes) {
        this.notes = notes != null ? notes : "";
    }
    
    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }
    
    @Override
    public String toString() {
        return "BaseRequest{" +
                "id=" + id +
                ", url='" + url + '\'' +
                ", notes='" + notes + '\'' +
                '}';
    }
}
