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
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.swing.SwingUtils;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.ui.editor.HttpRequestEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.BorderFactory;
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

    // Color annotation components
    private JCheckBox useColorAnnotationCheckBox;
    private JComboBox<HighlightColor> colorSelector;

    // Add as Unauthenticated button (renamed from Remove Authentication)
    private JButton removeAuthButton;
    
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

        // Add Latest Compatible Request button
        JButton addLatestRequestBtn = new JButton("Add Latest Compatible Request");
        addLatestRequestBtn.setToolTipText("Search proxy history for the most recent POST request with /aura in URL and required parameters");
        addLatestRequestBtn.addActionListener(e -> addLatestCompatibleRequest());
        topPanel.add(addLatestRequestBtn);

        // Color annotation checkbox
        useColorAnnotationCheckBox = new JCheckBox("Use color annotation");
        useColorAnnotationCheckBox.setToolTipText("Also filter by annotation color when searching for compatible requests");
        useColorAnnotationCheckBox.addActionListener(e -> colorSelector.setEnabled(useColorAnnotationCheckBox.isSelected()));
        topPanel.add(useColorAnnotationCheckBox);

        // Color selector dropdown
        HighlightColor[] colors = {
            HighlightColor.RED,
            HighlightColor.ORANGE,
            HighlightColor.YELLOW,
            HighlightColor.GREEN,
            HighlightColor.CYAN,
            HighlightColor.BLUE,
            HighlightColor.PINK,
            HighlightColor.MAGENTA,
            HighlightColor.GRAY
        };

        colorSelector = new JComboBox<>(colors);
        colorSelector.setEnabled(false); // Initially disabled
        colorSelector.setToolTipText("Select the annotation color to filter by");

        // Custom renderer to show color names properly
        colorSelector.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof HighlightColor) {
                    HighlightColor color = (HighlightColor) value;
                    setText(color.name().toLowerCase().replace("_", " "));
                }
                return this;
            }
        });

        topPanel.add(colorSelector);

        // Add as Unauthenticated button (renamed from Remove Authentication)
        removeAuthButton = new JButton("Add as Unauthenticated");
        removeAuthButton.setToolTipText("Create a copy of the selected request with authentication removed (cookies, authorization headers, and aura.token)");
        removeAuthButton.setEnabled(false); // Initially disabled
        removeAuthButton.addActionListener(e -> removeAuthentication());
        topPanel.add(removeAuthButton);

        // Clear All Requests button
        JButton clearAllRequestsBtn = new JButton("Clear All Requests");
        clearAllRequestsBtn.setToolTipText("Remove all base requests from the list");
        clearAllRequestsBtn.addActionListener(e -> clearAllRequests());
        topPanel.add(clearAllRequestsBtn);

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

                // Check if this is a compatible Aura request (including color annotation if enabled)
                if (isCompatibleAuraRequest(proxyRequestResponse)) {
                    // Create BaseRequest and add it (convert ProxyHttpRequestResponse to HttpRequestResponse)
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                        proxyRequestResponse.finalRequest(),
                        proxyRequestResponse.originalResponse()
                    );

                    // Create notes with annotation color information
                    String notes = "Added from proxy history";
                    HighlightColor requestColor = proxyRequestResponse.annotations().highlightColor();
                    if (requestColor != null) {
                        notes += " [Color: " + requestColor.name().toLowerCase() + "]";
                    }

                    BaseRequest baseRequest = new BaseRequest(requestResponse, notes);
                    baseRequests.add(baseRequest);

                    // Refresh table and notify callback
                    refreshTable();
                    if (onRequestsChangedCallback != null) {
                        onRequestsChangedCallback.run();
                    }

                    String colorInfo = useColorAnnotationCheckBox.isSelected() ?
                        " (with " + ((HighlightColor) colorSelector.getSelectedItem()).name().toLowerCase() + " annotation)" : "";
                    api.logging().logToOutput("Added compatible Aura request: " + request.url() + colorInfo);

                    // Show non-blocking success message
                    showNonBlockingMessage("✓ Successfully added compatible Aura request" + colorInfo + ":\n" + request.url(), "success");
                    return;
                }
            }

            // No compatible request found
            String colorFilterInfo = useColorAnnotationCheckBox.isSelected() ?
                "\n• " + ((HighlightColor) colorSelector.getSelectedItem()).name().toLowerCase() + " annotation color" : "";
            api.logging().logToOutput("No compatible Aura request found in proxy history");
            showNonBlockingMessage(
                "⚠ No compatible Aura request found in proxy history.\n\n" +
                "Looking for POST requests with:\n" +
                "• '/aura' in URL path\n" +
                "• 'message' parameter\n" +
                "• 'aura.token' parameter\n" +
                "• 'aura.context' parameter" + colorFilterInfo,
                "warning"
            );

        } catch (Exception e) {
            api.logging().logToError("Error searching proxy history: " + e.getMessage());
            showNonBlockingMessage("❌ Error searching proxy history: " + e.getMessage(), "error");
        }
    }

    /**
     * Show non-blocking message using a temporary status label
     */
    private void showNonBlockingMessage(String message, String type) {
        SwingUtilities.invokeLater(() -> {
            // Create a temporary notification panel
            JPanel notificationPanel = new JPanel(new BorderLayout());

            // Handle multi-line messages without HTML
            String displayMessage = message.replace("\n", " | ");
            JLabel messageLabel = new JLabel(" " + displayMessage + " ");
            messageLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // Set colors based on message type
            Color backgroundColor;
            Color textColor = Color.WHITE;
            switch (type.toLowerCase()) {
                case "success":
                    backgroundColor = new Color(76, 175, 80); // Green
                    break;
                case "warning":
                    backgroundColor = new Color(255, 152, 0); // Orange
                    break;
                case "error":
                    backgroundColor = new Color(244, 67, 54); // Red
                    break;
                default:
                    backgroundColor = new Color(33, 150, 243); // Blue
                    break;
            }

            notificationPanel.setBackground(backgroundColor);
            messageLabel.setForeground(textColor);
            messageLabel.setOpaque(false);
            notificationPanel.add(messageLabel, BorderLayout.CENTER);

            // Add close button
            JButton closeBtn = new JButton("×");
            closeBtn.setPreferredSize(new Dimension(25, 25));
            closeBtn.setBackground(backgroundColor);
            closeBtn.setForeground(textColor);
            closeBtn.setBorderPainted(false);
            closeBtn.setFocusPainted(false);
            closeBtn.addActionListener(e -> {
                mainPanel.remove(notificationPanel);
                mainPanel.revalidate();
                mainPanel.repaint();
            });
            notificationPanel.add(closeBtn, BorderLayout.EAST);

            // Add to top of main panel
            mainPanel.add(notificationPanel, BorderLayout.SOUTH);
            mainPanel.revalidate();
            mainPanel.repaint();

            // Auto-hide after 5 seconds
            Timer timer = ThreadManager.createManagedTimer(5000, e -> {
                mainPanel.remove(notificationPanel);
                mainPanel.revalidate();
                mainPanel.repaint();
            });
            timer.setRepeats(false);
            timer.start();
        });
    }

    /**
     * Check if a proxy request is a compatible Aura request (including color annotation check)
     */
    private boolean isCompatibleAuraRequest(ProxyHttpRequestResponse proxyRequestResponse) {
        try {
            HttpRequest request = proxyRequestResponse.finalRequest();

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

            if (!hasMessage || !hasAuraToken || !hasAuraContext) {
                return false;
            }

            // Check color annotation if enabled
            if (useColorAnnotationCheckBox.isSelected()) {
                HighlightColor selectedColor = (HighlightColor) colorSelector.getSelectedItem();
                if (selectedColor != null) {
                    // Check if the proxy request has the selected annotation color
                    HighlightColor requestColor = proxyRequestResponse.annotations().highlightColor();
                    if (!selectedColor.equals(requestColor)) {
                        return false;
                    }
                }
            }

            return true;

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
                // Update Add as Unauthenticated button state - enable only when exactly 1 request is selected
                removeAuthButton.setEnabled(requestTable.getSelectedRowCount() == 1);
            }
        });
    }
    
    private void setupRequestViewer() {
        // Add the native Burp HTTP request editor component
        Component editorComponent = requestEditor.uiComponent();
        requestViewerPanel.add(editorComponent, BorderLayout.CENTER);

        // Make the editor read-only by disabling the component
        // Users should use Repeater for modifications and "Send to Auraditor" to add edited requests
        setComponentEnabled(editorComponent, false);
    }

    /**
     * Recursively disable/enable a component and all its children
     */
    private void setComponentEnabled(Component component, boolean enabled) {
        component.setEnabled(enabled);
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                setComponentEnabled(child, enabled);
            }
        }
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
     * Show context menu with options for selected requests
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

            // Add as Unauthenticated menu item - only show when exactly 1 request is selected
            if (requestTable.getSelectedRowCount() == 1) {
                JMenuItem addUnauthenticatedItem = new JMenuItem("Add as Unauthenticated");
                addUnauthenticatedItem.addActionListener(ev -> removeAuthentication());
                contextMenu.add(addUnauthenticatedItem);
                contextMenu.addSeparator();
            }

            // Delete menu item
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
                api.userInterface().swingUtils().suiteFrame(),
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
        Timer timer = ThreadManager.createManagedTimer(1000, e -> {
            requestTable.setSelectionBackground(originalSelectionColor);
        });
        timer.setRepeats(false);
        timer.start();
    }

    /**
     * Remove authentication from the selected request and add it as a new base request
     */
    private void removeAuthentication() {
        int selectedRow = requestTable.getSelectedRow();
        if (selectedRow < 0 || selectedRow >= baseRequests.size()) {
            return;
        }

        BaseRequest selectedRequest = baseRequests.get(selectedRow);
        HttpRequestResponse originalRequestResponse = selectedRequest.getRequestResponse();

        try {
            // Start with the original request
            HttpRequest originalRequest = originalRequestResponse.request();

            // Get the original body and modify aura.token
            String originalBody = originalRequest.bodyToString();
            String modifiedBody = originalBody;
            if (originalBody.contains("aura.token=")) {
                // Replace aura.token value with "undefined"
                modifiedBody = originalBody.replaceAll("aura\\.token=[^&]*", "aura.token=undefined");
            }

            // Create modified request: remove headers and update body
            HttpRequest modifiedRequest = originalRequest
                .withBody(modifiedBody)
                .withRemovedHeader("Cookie")
                .withRemovedHeader("Authorization");

            HttpRequestResponse modifiedRequestResponse = HttpRequestResponse.httpRequestResponse(
                modifiedRequest,
                originalRequestResponse.response()
            );

            // Create new base request with "Unauthenticated" note
            BaseRequest newBaseRequest = new BaseRequest(modifiedRequestResponse, "Unauthenticated");
            baseRequests.add(newBaseRequest);

            // Refresh table and notify callback
            tableModel.fireTableDataChanged();
            if (onRequestsChangedCallback != null) {
                onRequestsChangedCallback.run();
            }

            showNonBlockingMessage("Created unauthenticated copy of request: " + selectedRequest.getUrl(), "success");

        } catch (Exception e) {
            api.logging().logToError("Error removing authentication: " + e.getMessage());
            showNonBlockingMessage("Error removing authentication: " + e.getMessage(), "error");
        }
    }

    /**
     * Clear all base requests from the list
     */
    private void clearAllRequests() {
        if (baseRequests.isEmpty()) {
            showNonBlockingMessage("No requests to clear", "warning");
            return;
        }

        // Confirm if there are multiple requests
        if (baseRequests.size() > 1) {
            int result = JOptionPane.showConfirmDialog(
                api.userInterface().swingUtils().suiteFrame(),
                "Are you sure you want to clear all " + baseRequests.size() + " base requests?",
                "Confirm Clear All",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }

        // Clear all requests
        int clearedCount = baseRequests.size();
        baseRequests.clear();

        // Refresh table and clear request viewer
        refreshTable();
        HttpRequest emptyRequest = HttpRequest.httpRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        requestEditor.setRequest(emptyRequest);

        // Notify callback that requests have changed
        if (onRequestsChangedCallback != null) {
            onRequestsChangedCallback.run();
        }

        showNonBlockingMessage("Cleared " + clearedCount + " base request" + (clearedCount == 1 ? "" : "s"), "success");
        api.logging().logToOutput("Cleared " + clearedCount + " base request(s)");
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

    /**
     * Cleanup method to properly dispose of resources when extension is unloaded
     */
    public void cleanup() {
        try {
            // Clear table data
            if (baseRequests != null) {
                baseRequests.clear();
            }

            api.logging().logToOutput("BaseRequestsTab cleanup completed");
        } catch (Exception e) {
            api.logging().logToError("Error during BaseRequestsTab cleanup: " + e.getMessage());
        }
    }
}
