/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Main Auraditor suite tab providing comprehensive Lightning/Aura auditing capabilities
 */
public class AuraditorSuiteTab {
    
    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final JTabbedPane tabbedPane;
    private final BaseRequestsTab baseRequestsTab;
    private final ActionsTab actionsTab;
    private final List<BaseRequest> baseRequests;
    private final JTabbedPane resultsTabbedPane;
    
    public AuraditorSuiteTab(MontoyaApi api) {
        this.api = api;
        this.baseRequests = new ArrayList<>();
        
        // Create main panel
        this.mainPanel = new JPanel(new BorderLayout());
        
        // Create tabbed pane for sub-tabs
        this.tabbedPane = new JTabbedPane();
        
        // Create results tabbed pane for dynamic result tabs
        this.resultsTabbedPane = new JTabbedPane();
        this.resultsTabbedPane.addTab("No Results", new JLabel("No results yet", SwingConstants.CENTER));
        
        // Create and add Base Requests tab
        this.baseRequestsTab = new BaseRequestsTab(api, baseRequests);
        this.tabbedPane.addTab("Base Requests", baseRequestsTab.getComponent());
        
        // Create and add Actions tab with result callback
        this.actionsTab = new ActionsTab(api, baseRequests, new ActionsTab.ResultTabCallback() {
            @Override
            public void createResultTab(String resultId, String content) {
                AuraditorSuiteTab.this.createResultTab(resultId, content);
            }
            
            @Override
            public void createDiscoveryResultTab(String resultId, ActionsTab.DiscoveryResult discoveryResult) {
                AuraditorSuiteTab.this.createDiscoveryResultTab(resultId, discoveryResult);
            }
            
            @Override
            public void createObjectByNameTab(String resultId, ActionsTab.ObjectByNameResult objectByNameResult) {
                AuraditorSuiteTab.this.createObjectByNameTab(resultId, objectByNameResult);
            }
            
            @Override
            public void updateObjectByNameTab(String resultId, ActionsTab.ObjectByNameResult objectByNameResult) {
                AuraditorSuiteTab.this.updateObjectByNameTabWithoutSwitching(resultId, objectByNameResult);
            }
        });
        this.tabbedPane.addTab("Actions", actionsTab.getComponent());
        
        // Set up callback for BaseRequestsTab to notify Actions tab when requests change
        this.baseRequestsTab.setOnRequestsChangedCallback(() -> {
            actionsTab.refreshRequests();
        });
        
        // Add placeholder tab for future functionality
        JPanel placeholderTab = new JPanel(new BorderLayout());
        placeholderTab.add(new JLabel("Results will be displayed here", SwingConstants.CENTER));
        this.tabbedPane.addTab("Results", resultsTabbedPane);
        
        // Add tab change listener to handle empty actions tab
        this.tabbedPane.addChangeListener(e -> {
            int selectedIndex = tabbedPane.getSelectedIndex();
            if (selectedIndex == 1) { // Actions tab
                if (!actionsTab.hasRequests()) {
                    // Show message but keep user on Actions tab so they can see the feedback
                    SwingUtilities.invokeLater(() -> {
                        actionsTab.showEmptyStateMessage();
                        // Don't switch tabs - let user see the status message and understand what to do
                    });
                }
            }
        });
        
        // Add tabbed pane to main panel - no header needed
        this.mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }
    
    /**
     * Create a new result tab with the given ID and content
     */
    private void createResultTab(String resultId, String content) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 && 
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }
            
            // Create content panel for the result
            JPanel resultPanel = new JPanel(new BorderLayout());
            JTextArea textArea = new JTextArea(content);
            textArea.setEditable(false);
            textArea.setWrapStyleWord(true);
            textArea.setLineWrap(true);
            resultPanel.add(new JScrollPane(textArea), BorderLayout.CENTER);
            
            // Add the new result tab
            resultsTabbedPane.addTab(resultId, resultPanel);
            
            // Switch to the new tab
            resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            
            // Switch to Results tab in main tabbed pane
            tabbedPane.setSelectedIndex(2); // Results tab index
        });
    }
    
    /**
     * Create a new discovery result tab with structured data
     */
    private void createDiscoveryResultTab(String resultId, ActionsTab.DiscoveryResult discoveryResult) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 && 
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }
            
            // Create discovery result panel
            ActionsTab.DiscoveryResultPanel discoveryPanel = new ActionsTab.DiscoveryResultPanel(discoveryResult);
            
            // Add the new result tab
            resultsTabbedPane.addTab(resultId, discoveryPanel);
            
            // Switch to the new tab
            resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            
            // Switch to Results tab in main tabbed pane
            tabbedPane.setSelectedIndex(2); // Results tab index
        });
    }
    
    /**
     * Create or update the Object by Name result tab with structured data
     */
    private void createObjectByNameTab(String resultId, ActionsTab.ObjectByNameResult objectByNameResult) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 && 
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }
            
            // Check if Object by Name tab already exists
            int existingTabIndex = -1;
            for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
                if (resultId.equals(resultsTabbedPane.getTitleAt(i))) {
                    existingTabIndex = i;
                    break;
                }
            }
            
            // Create object by name result panel
            ActionsTab.ObjectByNameResultPanel objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult);
            
            if (existingTabIndex >= 0) {
                // Update existing tab
                resultsTabbedPane.setComponentAt(existingTabIndex, objectByNamePanel);
                resultsTabbedPane.setSelectedIndex(existingTabIndex);
            } else {
                // Add new tab
                resultsTabbedPane.addTab(resultId, objectByNamePanel);
                resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            }
            
            // Switch to Results tab in main tabbed pane
            tabbedPane.setSelectedIndex(2); // Results tab index
        });
    }
    
    /**
     * Update an existing object by name tab without switching to Results tab
     */
    private void updateObjectByNameTabWithoutSwitching(String resultId, ActionsTab.ObjectByNameResult objectByNameResult) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 && 
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }
            
            // Check if Object by Name tab already exists
            int existingTabIndex = -1;
            for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
                if (resultId.equals(resultsTabbedPane.getTitleAt(i))) {
                    existingTabIndex = i;
                    break;
                }
            }
            
            // Create object by name result panel
            ActionsTab.ObjectByNameResultPanel objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult);
            
            if (existingTabIndex >= 0) {
                // Update existing tab without switching
                resultsTabbedPane.setComponentAt(existingTabIndex, objectByNamePanel);
                // Don't call setSelectedIndex to avoid automatic switching
            } else {
                // Add new tab without switching
                resultsTabbedPane.addTab(resultId, objectByNamePanel);
                // Don't call setSelectedIndex to avoid automatic switching
            }
            
            // Don't switch to Results tab - this is the key difference
            // tabbedPane.setSelectedIndex(2); // This line is intentionally omitted
        });
    }
    
    /**
     * Get the main UI component for this tab
     * 
     * @return the main panel component
     */
    public Component getComponent() {
        return mainPanel;
    }
    
    /**
     * Add a request to the base requests for analysis
     * Called when user selects "Send to Auraditor" from context menu
     * 
     * @param requestResponse The request/response to add
     */
    public void addBaseRequest(HttpRequestResponse requestResponse) {
        // Add timestamp when adding from context menu
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String timestamp = now.format(formatter);

        // Try to find annotation color by searching proxy history for matching request
        String notes = "Added via context menu at " + timestamp;
        String requestUrl = requestResponse.request().url();

        // Search proxy history for matching request to get annotation color
        java.util.Optional<burp.api.montoya.proxy.ProxyHttpRequestResponse> matchingProxyRequest = api.proxy().history().stream()
            .filter(proxyReq -> proxyReq.finalRequest().url().equals(requestUrl))
            .findFirst();

        if (matchingProxyRequest.isPresent()) {
            burp.api.montoya.core.HighlightColor requestColor = matchingProxyRequest.get().annotations().highlightColor();
            if (requestColor != null) {
                notes += " [Color: " + requestColor.name().toLowerCase() + "]";
            }
        }

        // Call the overloaded method with the complete notes
        addBaseRequest(requestResponse, notes);
    }
    
    /**
     * Add a request to the base requests for analysis with notes
     * 
     * @param requestResponse The request/response to add
     * @param notes Initial notes for the request
     */
    public void addBaseRequest(HttpRequestResponse requestResponse, String notes) {
        BaseRequest baseRequest = new BaseRequest(requestResponse, notes);
        baseRequests.add(baseRequest);
        baseRequestsTab.refreshTable();
        
        // Refresh the actions tab to update the request selector
        actionsTab.refreshRequests();
        
        // Switch to Base Requests tab to show the newly added request
        tabbedPane.setSelectedIndex(0);
        
        // Provide visual feedback by temporarily changing header color
        showVisualFeedback();
        
        api.logging().logToOutput("Added request to Auraditor: " + baseRequest.getUrl());
    }
    
    /**
     * Provide visual feedback when a request is added by briefly changing the tab color only
     */
    private void showVisualFeedback() {
        SwingUtilities.invokeLater(() -> {
            // Target the Base Requests tab (index 0)
            int baseRequestsTabIndex = 0;
            
            // Only change tab color briefly, no text changes
            tabbedPane.setForegroundAt(baseRequestsTabIndex, Color.ORANGE);
            
            // Create timer to revert back to normal after 1 second
            Timer timer = new Timer(1000, e -> {
                tabbedPane.setForegroundAt(baseRequestsTabIndex, null); // Revert to default color
            });
            timer.setRepeats(false);
            timer.start();
        });
    }
    
    /**
     * Get the number of base requests currently stored
     * 
     * @return the count of base requests
     */
    public int getBaseRequestCount() {
        return baseRequests.size();
    }
}
