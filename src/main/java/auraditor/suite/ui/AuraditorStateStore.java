/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Saves and loads base requests and result tabs in the Burp project file,
 * so they survive extension reloads and Burp restarts.
 */
public class AuraditorStateStore {

    private static final String BASE_REQUESTS_KEY = "base_requests";
    private static final String BASE_REQUESTS_META_KEY = "base_requests_meta";
    private static final String RESULT_TABS_KEY = "result_tabs";

    private final MontoyaApi api;
    private final ObjectMapper objectMapper = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public AuraditorStateStore(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Save all base requests. Request/response bytes use Burp's native storage; IDs and notes are kept as JSON.
     */
    public void saveBaseRequests(List<BaseRequest> baseRequests) {
        try {
            PersistedList<HttpRequestResponse> requestResponses = PersistedList.persistedHttpRequestResponseList();
            List<BaseRequestMeta> metas = new ArrayList<>();
            for (BaseRequest baseRequest : baseRequests) {
                requestResponses.add(baseRequest.getRequestResponse());
                metas.add(new BaseRequestMeta(baseRequest));
            }

            PersistedObject data = api.persistence().extensionData();
            data.setHttpRequestResponseList(BASE_REQUESTS_KEY, requestResponses);
            data.setString(BASE_REQUESTS_META_KEY, objectMapper.writeValueAsString(metas));
        } catch (Exception e) {
            api.logging().logToError("Failed to save base requests to project file: " + e.getMessage());
        }
    }

    public List<BaseRequest> loadBaseRequests() {
        List<BaseRequest> baseRequests = new ArrayList<>();
        try {
            PersistedObject data = api.persistence().extensionData();
            PersistedList<HttpRequestResponse> requestResponses = data.getHttpRequestResponseList(BASE_REQUESTS_KEY);
            String metaJson = data.getString(BASE_REQUESTS_META_KEY);
            if (requestResponses == null || metaJson == null) {
                return baseRequests;
            }

            BaseRequestMeta[] metas = objectMapper.readValue(metaJson, BaseRequestMeta[].class);
            for (int i = 0; i < requestResponses.size() && i < metas.length; i++) {
                baseRequests.add(new BaseRequest(metas[i].id, requestResponses.get(i), metas[i].notes));
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load base requests from project file: " + e.getMessage());
        }
        return baseRequests;
    }

    public void saveResultTabs(List<ResultTabState> tabs) {
        try {
            api.persistence().extensionData().setString(RESULT_TABS_KEY, objectMapper.writeValueAsString(tabs));
        } catch (Exception e) {
            api.logging().logToError("Failed to save result tabs to project file: " + e.getMessage());
        }
    }

    public List<ResultTabState> loadResultTabs() {
        try {
            String json = api.persistence().extensionData().getString(RESULT_TABS_KEY);
            if (json != null && !json.isEmpty()) {
                return new ArrayList<>(List.of(objectMapper.readValue(json, ResultTabState[].class)));
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load result tabs from project file: " + e.getMessage());
        }
        return new ArrayList<>();
    }

    /**
     * Snapshot a results tab panel, or return null if the component is not a persistable result panel
     */
    public static ResultTabState fromPanel(String title, java.awt.Component component) {
        ResultTabState state = new ResultTabState();
        state.title = title;

        if (component instanceof ActionsTab.DiscoveryResultPanel) {
            ActionsTab.DiscoveryResult result = ((ActionsTab.DiscoveryResultPanel) component).getDiscoveryResult();
            state.type = ResultTabState.DISCOVERED_OBJECTS;
            state.defaultObjects = new ArrayList<>(result.getDefaultObjects());
            state.customObjects = new ArrayList<>(result.getCustomObjects());
        } else if (component instanceof ActionsTab.DiscoveredRoutesResultPanel) {
            ActionsTab.RouteDiscoveryResult result = ((ActionsTab.DiscoveredRoutesResultPanel) component).getRouteDiscoveryResult();
            state.type = ResultTabState.DISCOVERED_ROUTES;
            state.routes = new LinkedHashMap<>(result.getRouteEntries());
        } else if (component instanceof ActionsTab.ObjectByNameResultPanel) {
            state.type = ResultTabState.OBJECTS;
            state.entries = ((ActionsTab.ObjectByNameResultPanel) component).getObjectEntries();
        } else if (component instanceof ActionsTab.RetrievedRecordsResultPanel) {
            ActionsTab.RetrievedRecordsResultPanel panel = (ActionsTab.RetrievedRecordsResultPanel) component;
            state.type = ResultTabState.RECORDS;
            state.entries = panel.getRecords();
            state.requestId = panel.getRequestId();
        } else {
            return null;
        }
        return state;
    }

    /**
     * JSON form of a base request's metadata
     */
    public static class BaseRequestMeta {
        public int id;
        public String notes;

        public BaseRequestMeta() {
        }

        public BaseRequestMeta(BaseRequest baseRequest) {
            this.id = baseRequest.getId();
            this.notes = baseRequest.getNotes();
        }
    }

    /**
     * JSON form of one results tab
     */
    public static class ResultTabState {
        public static final String DISCOVERED_OBJECTS = "discovered_objects";
        public static final String DISCOVERED_ROUTES = "discovered_routes";
        public static final String OBJECTS = "objects";
        public static final String RECORDS = "records";

        public String type;
        public String title;
        public List<String> defaultObjects;
        public List<String> customObjects;
        public Map<String, List<String>> routes;
        public Map<String, String> entries;
        public String requestId;
    }
}
