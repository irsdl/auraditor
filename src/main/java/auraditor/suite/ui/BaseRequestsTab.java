/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Tab displaying base requests in a table format with request viewer/editor
 */
public class BaseRequestsTab {
    
    private final MontoyaApi api;
    private final List<BaseRequest> baseRequests;
    private final JPanel mainPanel;
    private final JTable requestTable;
    private final BaseRequestTableModel tableModel;
    private final JSplitPane splitPane;
    private final JPanel requestViewerPanel;
    private final HttpRequestEditor requestEditor;
    private Runnable onRequestsChangedCallback; // Callback for when requests are deleted
    
    public BaseRequestsTab(MontoyaApi api, List<BaseRequest> baseRequests) {
        this.api = api;
        this.baseRequests = baseRequests;
        
        // Create main panel
        this.mainPanel = new JPanel(new BorderLayout());

        // Create top panel with button
        JPanel topPanel = createTopPanel();
        this.mainPanel.add(topPanel, BorderLayout.NORTH);

        // Create table model and table
        this.tableModel = new BaseRequestTableModel();
        this.requestTable = new JTable(tableModel);
        setupTable();

        // Create request viewer panel
        this.requestViewerPanel = new JPanel(new BorderLayout());
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        setupRequestViewer();

        // Create split pane with table on top and request viewer on bottom
        JScrollPane tableScrollPane = new JScrollPane(requestTable);
        this.splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, requestViewerPanel);
        this.splitPane.setDividerLocation(300); // Set initial divider position
        this.splitPane.setResizeWeight(0.6); // Give more space to table

        // Add split pane to center
        this.mainPanel.add(splitPane, BorderLayout.CENTER);
    }

    /**
     * Create top panel with "Add Latest Compatible Request" button
     */
    private JPanel createTopPanel() {
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JButton addLatestRequestBtn = new JButton("Add Latest Compatible Request");
        addLatestRequestBtn.setToolTipText("Search proxy history for the most recent POST request with /aura in URL and required parameters");
        addLatestRequestBtn.addActionListener(e -> addLatestCompatibleRequest());

        topPanel.add(addLatestRequestBtn);

        return topPanel;
    }

    /**
     * Search proxy history for the latest compatible Aura request and add it to base requests
     */
    private void addLatestCompatibleRequest() {
        try {
            api.logging().logToOutput("Searching proxy history for latest compatible Aura request...");

            // Search proxy history for compatible requests
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();

            // Search from most recent to oldest
            for (int i = proxyHistory.size() - 1; i >= 0; i--) {
                ProxyHttpRequestResponse proxyRequestResponse = proxyHistory.get(i);
                HttpRequest request = proxyRequestResponse.finalRequest();

                // Check if this is a compatible Aura request
                if (isCompatibleAuraRequest(request)) {
                    // Create BaseRequest and add it (convert ProxyHttpRequestResponse to HttpRequestResponse)
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                        proxyRequestResponse.finalRequest(),
                        proxyRequestResponse.originalResponse()
                    );
                    BaseRequest baseRequest = new BaseRequest(requestResponse, "Added from proxy history");
                    baseRequests.add(baseRequest);

                    // Refresh table and notify callback
                    refreshTable();
                    if (onRequestsChangedCallback != null) {
                        onRequestsChangedCallback.run();
                    }

                    api.logging().logToOutput("Added compatible Aura request: " + request.url());

                    // Show success message
                    JOptionPane.showMessageDialog(
                        mainPanel,
                        "Successfully added compatible Aura request:\n" + request.url(),
                        "Request Added",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                    return;
                }
            }

            // No compatible request found
            api.logging().logToOutput("No compatible Aura request found in proxy history");
            JOptionPane.showMessageDialog(
                mainPanel,
                "No compatible Aura request found in proxy history.\n\n" +
                "Looking for POST requests with:\n" +
                "• '/aura' in URL path\n" +
                "• 'message' parameter\n" +
                "• 'aura.token' parameter\n" +
                "• 'aura.context' parameter",
                "No Compatible Request Found",
                JOptionPane.WARNING_MESSAGE
            );

        } catch (Exception e) {
            api.logging().logToError("Error searching proxy history: " + e.getMessage());
            JOptionPane.showMessageDialog(
                mainPanel,
                "Error searching proxy history: " + e.getMessage(),
                "Search Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    /**
     * Check if a request is a compatible Aura request
     */
    private boolean isCompatibleAuraRequest(HttpRequest request) {
        try {
            // Check if it's a POST request
            if (!request.method().equals("POST")) {
                return false;
            }

            // Check if URL contains "/aura"
            String url = request.url();
            if (!url.contains("/aura")) {
                return false;
            }

            // Check for required parameters in the POST body
            String body = request.bodyToString();

            boolean hasMessage = body.contains("message=") || body.contains("\"message\":");
            boolean hasAuraToken = body.contains("aura.token=") || body.contains("\"aura.token\":");
            boolean hasAuraContext = body.contains("aura.context=") || body.contains("\"aura.context\":");

            return hasMessage && hasAuraToken && hasAuraContext;

        } catch (Exception e) {
            api.logging().logToError("Error checking request compatibility: " + e.getMessage());
            return false;
        }
    }

    private void setupTable() {
        // Set column widths
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // ID
        requestTable.getColumnModel().getColumn(1).setPreferredWidth(400); // URL
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(200); // Notes
        
        // Allow multiple selection for deletion
        requestTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        
        // Add click listener to show request details and handle context menu
        requestTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1 && e.getButton() == MouseEvent.BUTTON1) { // Left-click only
                    int selectedRow = requestTable.getSelectedRow();
                    if (selectedRow >= 0 && selectedRow < baseRequests.size()) {
                        showRequestDetails(baseRequests.get(selectedRow));
                    }
                }
            }
            
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }
            
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e);
                }
            }
        });
        
        // Add key listener for Del key
        requestTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_DELETE) {
                    deleteSelectedRequests();
                }
            }
        });
        
        // Add selection listener
        requestTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = requestTable.getSelectedRow();
                if (selectedRow >= 0 && selectedRow < baseRequests.size()) {
                    showRequestDetails(baseRequests.get(selectedRow));
                }
            }
        });
    }
    
    private void setupRequestViewer() {
        // Add the native Burp HTTP request editor component
        requestViewerPanel.add(requestEditor.uiComponent(), BorderLayout.CENTER);
    }
    
    private void showRequestDetails(BaseRequest baseRequest) {
        if (baseRequest == null || baseRequest.getRequestResponse() == null) {
            // Create a minimal HTTP request to show "no data available"
            HttpRequest emptyRequest = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            requestEditor.setRequest(emptyRequest);
            return;
        }
        
        HttpRequest request = baseRequest.getRequestResponse().request();
        if (request == null) {
            // Create a minimal HTTP request to show "no data available"  
            HttpRequest emptyRequest = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            requestEditor.setRequest(emptyRequest);
            return;
        }
        
        // Set the actual request in the editor - this provides full Burp editing capabilities
        requestEditor.setRequest(request);
    }
    
    /**
     * Show context menu for deleting requests
     */
    private void showContextMenu(MouseEvent e) {
        int rowAtPoint = requestTable.rowAtPoint(e.getPoint());
        
        // If clicked on a row that's not selected, select it
        if (rowAtPoint >= 0 && !requestTable.isRowSelected(rowAtPoint)) {
            requestTable.setRowSelectionInterval(rowAtPoint, rowAtPoint);
        }
        
        // Only show menu if there are selected rows
        if (requestTable.getSelectedRowCount() > 0) {
            JPopupMenu contextMenu = new JPopupMenu();
            JMenuItem deleteItem = new JMenuItem("Delete Selected Request(s)");
            deleteItem.addActionListener(ev -> deleteSelectedRequests());
            contextMenu.add(deleteItem);
            contextMenu.show(requestTable, e.getX(), e.getY());
        }
    }
    
    /**
     * Delete selected requests from the table
     */
    private void deleteSelectedRequests() {
        int[] selectedRows = requestTable.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }
        
        // Confirm deletion if multiple requests selected
        if (selectedRows.length > 1) {
            int result = JOptionPane.showConfirmDialog(
                mainPanel,
                "Are you sure you want to delete " + selectedRows.length + " requests?",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }
        
        // Delete in reverse order to maintain indices
        List<BaseRequest> toDelete = new ArrayList<>();
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            int row = selectedRows[i];
            if (row >= 0 && row < baseRequests.size()) {
                toDelete.add(baseRequests.get(row));
            }
        }
        
        // Remove the requests
        baseRequests.removeAll(toDelete);
        
        // Refresh the table
        refreshTable();
        
        // Notify that requests have changed (for Actions tab refresh)
        if (onRequestsChangedCallback != null) {
            onRequestsChangedCallback.run();
        }
        
        // Clear the request viewer if no requests left
        if (baseRequests.isEmpty()) {
            HttpRequest emptyRequest = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            requestEditor.setRequest(emptyRequest);
        }
    }
    
    /**
     * Set callback to be notified when requests are added or deleted
     */
    public void setOnRequestsChangedCallback(Runnable callback) {
        this.onRequestsChangedCallback = callback;
    }
    
    public Component getComponent() {
        return mainPanel;
    }
    
    public void refreshTable() {
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            // If this is the first request, select it automatically
            if (baseRequests.size() == 1) {
                requestTable.setRowSelectionInterval(0, 0);
                showRequestDetails(baseRequests.get(0));
            } else if (baseRequests.size() > 1) {
                // Automatically select the latest (newly added) request
                int lastRow = baseRequests.size() - 1;
                requestTable.setRowSelectionInterval(lastRow, lastRow);
                showRequestDetails(baseRequests.get(lastRow));
                
                // Scroll to show the new request
                requestTable.scrollRectToVisible(requestTable.getCellRect(lastRow, 0, true));
                
                // Provide subtle visual feedback by briefly highlighting the new row
                highlightNewRequest(lastRow);
            }
        });
    }
    
    /**
     * Briefly highlight a newly added request row
     */
    private void highlightNewRequest(int rowIndex) {
        // Store original selection color
        Color originalSelectionColor = requestTable.getSelectionBackground();
        
        // Temporarily change selection color to orange
        requestTable.setSelectionBackground(Color.ORANGE);
        
        // Create timer to revert back to normal after 1 second
        Timer timer = new Timer(1000, e -> {
            requestTable.setSelectionBackground(originalSelectionColor);
        });
        timer.setRepeats(false);
        timer.start();
    }
    
    /**
     * Table model for displaying base requests
     */
    private class BaseRequestTableModel extends AbstractTableModel {
        private final String[] columnNames = {"ID", "URL", "Notes"};
        
        @Override
        public int getRowCount() {
            return baseRequests.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= baseRequests.size()) {
                return "";
            }
            
            BaseRequest request = baseRequests.get(rowIndex);
            switch (columnIndex) {
                case 0: return request.getId();
                case 1: return request.getUrl();
                case 2: return request.getNotes();
                default: return "";
            }
        }
        
        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            // Only notes column (column 2) is editable
            return columnIndex == 2;
        }
        
        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            if (rowIndex >= baseRequests.size() || columnIndex != 2) {
                return;
            }
            
            BaseRequest request = baseRequests.get(rowIndex);
            request.setNotes(value.toString());
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
