/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import auraditor.core.ThreadManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.swing.SwingUtils;

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
    private final java.util.Map<String, ActionsTab.ObjectByNameResultPanel> existingObjectPanels;
    private final SalesforceIdGeneratorManager generatorManager;

    public AuraditorSuiteTab(MontoyaApi api, SalesforceIdGeneratorManager generatorManager) {
        this.api = api;
        this.generatorManager = generatorManager;
        this.baseRequests = new ArrayList<>();
        this.existingObjectPanels = new java.util.HashMap<>();
        
        // Create main panel
        this.mainPanel = new JPanel(new BorderLayout());
        
        // Create tabbed pane for sub-tabs
        this.tabbedPane = new JTabbedPane();
        
        // Create results tabbed pane for dynamic result tabs
        this.resultsTabbedPane = new JTabbedPane();
        this.resultsTabbedPane.addTab("No Results", new JLabel("No results yet", SwingConstants.CENTER));

        // Add right-click context menu for tab deletion
        setupResultsTabContextMenu();
        
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

            @Override
            public void createRecordTab(String resultId, String recordId, String recordData, BaseRequest baseRequest) {
                AuraditorSuiteTab.this.createRecordTab(resultId, recordId, recordData, baseRequest);
            }

            @Override
            public void createDiscoveredRoutesTab(String resultId, ActionsTab.RouteDiscoveryResult routeDiscoveryResult) {
                AuraditorSuiteTab.this.createDiscoveredRoutesTab(resultId, routeDiscoveryResult);
            }

            @Override
            public void updateDiscoveredRoutesTab(String resultId, ActionsTab.RouteDiscoveryResult routeDiscoveryResult) {
                AuraditorSuiteTab.this.updateDiscoveredRoutesTab(resultId, routeDiscoveryResult);
            }

            public void createRetrievedRecordsTab(String resultId, String recordId, String recordData) {
                AuraditorSuiteTab.this.createRetrievedRecordsTab(resultId, recordId, recordData);
            }
        });
        this.tabbedPane.addTab("Actions", actionsTab.getComponent());
        
        // Set up callback for BaseRequestsTab to notify Actions tab when requests change
        this.baseRequestsTab.setOnRequestsChangedCallback(() -> {
            actionsTab.refreshRequests();
        });

        // Create and add Salesforce ID Lab tab
        SalesforceIdLabTab salesforceIdLabTab = new SalesforceIdLabTab(api, generatorManager);
        this.tabbedPane.addTab("Salesforce ID Lab", salesforceIdLabTab.getComponent());

        // Add placeholder tab for future functionality
        JPanel placeholderTab = new JPanel(new BorderLayout());
        placeholderTab.add(new JLabel("Results will be displayed here", SwingConstants.CENTER));
        this.tabbedPane.addTab("Results", resultsTabbedPane);

        // Create and add About tab
        AboutTab aboutTab = new AboutTab(api);
        this.tabbedPane.addTab("About", aboutTab.getComponent());

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
     * Switch to a tab by its name in the main tabbed pane
     * @param tabName The name of the tab to switch to
     */
    private void switchToTab(String tabName) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getTitleAt(i).equals(tabName)) {
                tabbedPane.setSelectedIndex(i);
                return;
            }
        }
        api.logging().logToError("Could not find tab with name: " + tabName);
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
            switchToTab("Results");
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
            ActionsTab.DiscoveryResultPanel discoveryPanel = new ActionsTab.DiscoveryResultPanel(discoveryResult, api);
            
            // Add the new result tab
            resultsTabbedPane.addTab(resultId, discoveryPanel);
            
            // Switch to the new tab
            resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            
            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
        });
    }

    /**
     * Create a new discovered routes result tab with route discovery result
     */
    private void createDiscoveredRoutesTab(String resultId, ActionsTab.RouteDiscoveryResult routeDiscoveryResult) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 &&
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }

            // Create discovered routes result panel
            ActionsTab.DiscoveredRoutesResultPanel routesPanel = new ActionsTab.DiscoveredRoutesResultPanel(routeDiscoveryResult, api);

            // Add the new result tab
            resultsTabbedPane.addTab(resultId, routesPanel);

            // Switch to the new tab
            resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);

            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
        });
    }

    /**
     * Update or create discovered routes result tab with route discovery result
     */
    private void updateDiscoveredRoutesTab(String resultId, ActionsTab.RouteDiscoveryResult routeDiscoveryResult) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 &&
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }

            // Check if Discovered Routes tab already exists
            int existingTabIndex = -1;
            for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
                if (resultId.equals(resultsTabbedPane.getTitleAt(i))) {
                    existingTabIndex = i;
                    break;
                }
            }

            if (existingTabIndex >= 0) {
                // Tab exists - update existing panel
                ActionsTab.DiscoveredRoutesResultPanel existingPanel =
                    (ActionsTab.DiscoveredRoutesResultPanel) resultsTabbedPane.getComponentAt(existingTabIndex);
                existingPanel.updateRouteDiscoveryResult(routeDiscoveryResult);

                // Switch to the updated tab
                resultsTabbedPane.setSelectedIndex(existingTabIndex);
            } else {
                // Tab doesn't exist - create new tab
                ActionsTab.DiscoveredRoutesResultPanel routesPanel =
                    new ActionsTab.DiscoveredRoutesResultPanel(routeDiscoveryResult, api);

                // Add the new result tab
                resultsTabbedPane.addTab(resultId, routesPanel);

                // Switch to the new tab
                resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            }

            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
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

            ActionsTab.ObjectByNameResultPanel objectByNamePanel;

            if (existingTabIndex >= 0) {
                // Tab exists - check if we have an existing panel to update
                objectByNamePanel = existingObjectPanels.get(resultId);
                if (objectByNamePanel != null) {
                    // Update existing panel instead of recreating
                    objectByNamePanel.updateWithNewData(objectByNameResult);
                } else {
                    // Create new panel (shouldn't happen, but safety fallback)
                    objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult, baseRequests, api);
                    existingObjectPanels.put(resultId, objectByNamePanel);
                    resultsTabbedPane.setComponentAt(existingTabIndex, objectByNamePanel);
                }
                resultsTabbedPane.setSelectedIndex(existingTabIndex);
            } else {
                // Create new tab and panel
                objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult, baseRequests, api);
                existingObjectPanels.put(resultId, objectByNamePanel);
                resultsTabbedPane.addTab(resultId, objectByNamePanel);
                resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            }
            
            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
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

            ActionsTab.ObjectByNameResultPanel objectByNamePanel;

            if (existingTabIndex >= 0) {
                // Tab exists - check if we have an existing panel to update
                objectByNamePanel = existingObjectPanels.get(resultId);
                if (objectByNamePanel != null) {
                    // Update existing panel instead of recreating
                    objectByNamePanel.updateWithNewData(objectByNameResult);
                } else {
                    // Create new panel (shouldn't happen, but safety fallback)
                    objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult, baseRequests, api);
                    existingObjectPanels.put(resultId, objectByNamePanel);
                    resultsTabbedPane.setComponentAt(existingTabIndex, objectByNamePanel);
                }
                // Don't call setSelectedIndex to avoid automatic switching
            } else {
                // Create new tab and panel without switching
                objectByNamePanel = new ActionsTab.ObjectByNameResultPanel(objectByNameResult, baseRequests, api);
                existingObjectPanels.put(resultId, objectByNamePanel);
                resultsTabbedPane.addTab(resultId, objectByNamePanel);
                // Don't call setSelectedIndex to avoid automatic switching
            }
            
            // Don't switch to Results tab - this is the key difference
            // tabbedPane.setSelectedIndex(2); // This line is intentionally omitted
        });
    }

    /**
     * Create a new retrieved records result tab with context menu support
     */
    private void createRecordTab(String resultId, String recordId, String recordData, BaseRequest baseRequest) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 &&
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }

            // Check if the specified resultId tab already exists
            ActionsTab.RetrievedRecordsResultPanel existingPanel = null;
            int existingTabIndex = -1;

            for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
                String tabTitle = resultsTabbedPane.getTitleAt(i);
                if (resultId.equals(tabTitle)) {
                    Component component = resultsTabbedPane.getComponentAt(i);
                    if (component instanceof ActionsTab.RetrievedRecordsResultPanel) {
                        existingPanel = (ActionsTab.RetrievedRecordsResultPanel) component;
                        existingTabIndex = i;
                        break;
                    }
                }
            }

            if (existingPanel != null) {
                // Add to existing tab
                existingPanel.addRecord(recordId, recordData);
                // Switch to the existing tab
                resultsTabbedPane.setSelectedIndex(existingTabIndex);
            } else {
                // Create new tab with context menu support
                ActionsTab.RetrievedRecordsResultPanel retrievedRecordsPanel =
                    new ActionsTab.RetrievedRecordsResultPanel(recordId, recordData, baseRequests, String.valueOf(baseRequest.getId()), api);

                // Add the new result tab with the specific resultId name
                resultsTabbedPane.addTab(resultId, retrievedRecordsPanel);

                // Switch to the new tab
                resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            }

            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
        });
    }

    /**
     * Create a new retrieved records result tab with raw data or add to existing tab
     */
    private void createRetrievedRecordsTab(String resultId, String recordId, String recordData) {
        SwingUtilities.invokeLater(() -> {
            // Remove "No Results" tab if it exists
            if (resultsTabbedPane.getTabCount() == 1 &&
                "No Results".equals(resultsTabbedPane.getTitleAt(0))) {
                resultsTabbedPane.removeTabAt(0);
            }

            // Check if "Retrieved Records" tab already exists
            ActionsTab.RetrievedRecordsResultPanel existingPanel = null;
            int existingTabIndex = -1;

            for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
                String tabTitle = resultsTabbedPane.getTitleAt(i);
                if ("Retrieved Records".equals(tabTitle)) {
                    Component component = resultsTabbedPane.getComponentAt(i);
                    if (component instanceof ActionsTab.RetrievedRecordsResultPanel) {
                        existingPanel = (ActionsTab.RetrievedRecordsResultPanel) component;
                        existingTabIndex = i;
                        break;
                    }
                }
            }

            if (existingPanel != null) {
                // Add to existing tab
                existingPanel.addRecord(recordId, recordData);

                // Switch to the existing tab
                resultsTabbedPane.setSelectedIndex(existingTabIndex);
            } else {
                // Create new tab without context menu support (legacy method)
                ActionsTab.RetrievedRecordsResultPanel retrievedRecordsPanel =
                    new ActionsTab.RetrievedRecordsResultPanel(recordId, recordData, baseRequests, null, api);

                // Add the new result tab with a fixed name for accumulation
                resultsTabbedPane.addTab("Retrieved Records", retrievedRecordsPanel);

                // Switch to the new tab
                resultsTabbedPane.setSelectedIndex(resultsTabbedPane.getTabCount() - 1);
            }

            // Switch to Results tab in main tabbed pane
            switchToTab("Results");
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
            Timer timer = ThreadManager.createManagedTimer(1000, e -> {
                tabbedPane.setForegroundAt(baseRequestsTabIndex, null); // Revert to default color
            });
            timer.setRepeats(false);
            timer.start();
        });
    }

    /**
     * Setup right-click context menu for results tabs
     */
    private void setupResultsTabContextMenu() {
        resultsTabbedPane.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showResultsTabContextMenu(e);
                }
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showResultsTabContextMenu(e);
                }
            }
        });
    }

    /**
     * Show context menu for results tab
     */
    private void showResultsTabContextMenu(java.awt.event.MouseEvent e) {
        // Find which tab was right-clicked
        int clickedTab = -1;
        for (int i = 0; i < resultsTabbedPane.getTabCount(); i++) {
            java.awt.Rectangle tabBounds = resultsTabbedPane.getBoundsAt(i);
            if (tabBounds != null && tabBounds.contains(e.getPoint())) {
                clickedTab = i;
                break;
            }
        }

        if (clickedTab >= 0) {
            String tabTitle = resultsTabbedPane.getTitleAt(clickedTab);

            // Don't show context menu for "No Results" tab
            if ("No Results".equals(tabTitle)) {
                return;
            }

            // Check if scan is in progress
            boolean scanInProgress = actionsTab.isProcessing();

            javax.swing.JPopupMenu popup = new javax.swing.JPopupMenu();
            javax.swing.JMenuItem deleteItem = new javax.swing.JMenuItem("Delete Tab");

            if (scanInProgress) {
                deleteItem.setEnabled(false);
                deleteItem.setToolTipText("Cannot delete tab while scan is in progress. Cancel the scan first.");
            } else {
                deleteItem.setToolTipText("Delete this results tab");
                final int tabIndex = clickedTab;
                deleteItem.addActionListener(actionEvent -> deleteResultsTab(tabIndex, tabTitle));
            }

            popup.add(deleteItem);
            popup.show(e.getComponent(), e.getX(), e.getY());
        }
    }

    /**
     * Delete a results tab and handle dependencies
     */
    private void deleteResultsTab(int tabIndex, String tabTitle) {
        SwingUtilities.invokeLater(() -> {
            // Show confirmation dialog
            int confirm = javax.swing.JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "Are you sure you want to delete the tab '" + tabTitle + "'?\nThis action cannot be undone.",
                "Confirm Tab Deletion",
                javax.swing.JOptionPane.YES_NO_OPTION,
                javax.swing.JOptionPane.WARNING_MESSAGE
            );

            if (confirm != javax.swing.JOptionPane.YES_OPTION) {
                return; // User cancelled
            }

            // Remove the tab
            resultsTabbedPane.removeTabAt(tabIndex);

            // Handle special cases based on tab title
            if (tabTitle.startsWith("Discovered Objects")) {
                // Reset discovery state in ActionsTab
                actionsTab.resetDiscoveryState();
                api.logging().logToOutput("Deleted discovery results tab: " + tabTitle);
            } else if (tabTitle.startsWith("Discovered Routes")) {
                // Reset route discovery state in ActionsTab
                actionsTab.resetRouteDiscoveryState();
                api.logging().logToOutput("Deleted route discovery results tab: " + tabTitle);
            } else if (tabTitle.startsWith("Objects") || tabTitle.startsWith("Retrieved Objects")) {
                // Clean up object results tracking
                existingObjectPanels.remove(tabTitle);
                api.logging().logToOutput("Deleted object results tab: " + tabTitle);
            } else if (tabTitle.startsWith("Retrieved Records")) {
                // Clean up record results tracking
                api.logging().logToOutput("Deleted record results tab: " + tabTitle);
            } else {
                api.logging().logToOutput("Deleted results tab: " + tabTitle);
            }

            // If no more tabs, add "No Results" tab back
            if (resultsTabbedPane.getTabCount() == 0) {
                resultsTabbedPane.addTab("No Results", new JLabel("No results yet", SwingConstants.CENTER));
            }
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

    /**
     * Cleanup method to properly dispose of resources when extension is unloaded
     */
    public void cleanup() {
        try {
            // Cleanup the actions tab which contains most threads
            if (actionsTab != null) {
                actionsTab.cleanup();
            }

            // Cleanup the base requests tab
            if (baseRequestsTab != null) {
                baseRequestsTab.cleanup();
            }

            // Clear any remaining UI components
            if (tabbedPane != null) {
                tabbedPane.removeAll();
            }
            if (resultsTabbedPane != null) {
                resultsTabbedPane.removeAll();
            }

            api.logging().logToOutput("AuraditorSuiteTab cleanup completed");
        } catch (Exception e) {
            api.logging().logToError("Error during AuraditorSuiteTab cleanup: " + e.getMessage());
        }
    }
}
