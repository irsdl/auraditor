/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All righ        this.findDefaultObjectsPresetBtn = new JButton("Get Objects with Wordlist");
        this.selectWordlistBtn = new JButton("Choose File...");
        this.usePresetWordlistCheckbox = new JCheckBox("Use built-in wordlist", true);
        this.cancelBtn = new JButton("Cancel");reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root     private void setupEventHandlers() {/opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Tab for launching different types of Lightning/Aura security scans
 */
public class ActionsTab {
    
    /**
     * Utility class for safe regex execution with timeout protection against ReDoS attacks
     */
    public static class SafeRegex {
        private static final int MAX_TIMEOUT_SECONDS = 10;
        private static final int MAX_MATCHES_PER_SEARCH = 10000;
        private static final int MAX_PATTERN_LENGTH = 1000;
        
        /**
         * Safely compile a regex pattern with basic validation
         */
        public static java.util.regex.Pattern safeCompile(String regex, int flags) throws java.util.regex.PatternSyntaxException {
            if (regex == null || regex.trim().isEmpty()) {
                throw new java.util.regex.PatternSyntaxException("Empty pattern", regex, -1);
            }
            
            if (regex.length() > MAX_PATTERN_LENGTH) {
                throw new java.util.regex.PatternSyntaxException("Pattern too long (max " + MAX_PATTERN_LENGTH + " chars)", regex, -1);
            }
            
            // Check for some common ReDoS patterns
            if (containsSuspiciousPatterns(regex)) {
                throw new java.util.regex.PatternSyntaxException("Potentially unsafe pattern detected", regex, -1);
            }
            
            return java.util.regex.Pattern.compile(regex, flags);
        }
        
        /**
         * Safely find matches with timeout protection
         */
        public static java.util.List<Integer> safeFind(java.util.regex.Pattern pattern, String text) {
            java.util.List<Integer> matches = new java.util.ArrayList<>();
            
            if (text == null || text.isEmpty()) {
                return matches;
            }
            
            // Use CompletableFuture with timeout for safe execution
            java.util.concurrent.CompletableFuture<java.util.List<Integer>> future = 
                java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    java.util.List<Integer> results = new java.util.ArrayList<>();
                    java.util.regex.Matcher matcher = pattern.matcher(text);
                    int matchCount = 0;
                    
                    while (matcher.find() && matchCount < MAX_MATCHES_PER_SEARCH) {
                        results.add(matcher.start());
                        matchCount++;
                        
                        // Check for thread interruption
                        if (Thread.currentThread().isInterrupted()) {
                            break;
                        }
                    }
                    
                    return results;
                });
            
            try {
                return future.get(MAX_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                throw new RuntimeException("Regex search timed out after " + MAX_TIMEOUT_SECONDS + " seconds - potentially unsafe pattern");
            } catch (Exception e) {
                future.cancel(true);
                throw new RuntimeException("Regex search failed: " + e.getMessage());
            }
        }
        
        /**
         * Safely check if pattern matches with timeout protection
         */
        public static boolean safeMatches(java.util.regex.Pattern pattern, String text) {
            if (text == null || text.isEmpty()) {
                return false;
            }
            
            java.util.concurrent.CompletableFuture<Boolean> future = 
                java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    return pattern.matcher(text).find();
                });
            
            try {
                return future.get(MAX_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                return false; // Treat timeout as no match
            } catch (Exception e) {
                future.cancel(true);
                return false; // Treat errors as no match
            }
        }
        
        /**
         * Check for common ReDoS patterns that could cause exponential backtracking
         */
        private static boolean containsSuspiciousPatterns(String regex) {
            // Common ReDoS patterns to detect
            String[] suspiciousPatterns = {
                "\\(.*\\)\\*",           // (.*)*
                "\\(.*\\)\\+",           // (.*)+ 
                "\\(.\\*\\)\\{",         // (.*){n,m}
                "\\(.\\+\\)\\*",         // (.+)*
                "\\(.\\+\\)\\+",         // (.+)+
                "\\(.\\+\\)\\{",         // (.+){n,m}
                "\\(.*\\?.*\\)\\*",      // (.*?.*)*
                "\\(.*\\?.*\\)\\+",      // (.*?.*)+
                "\\([^\\)]*\\*[^\\)]*\\)\\*", // Complex nested quantifiers
                "\\([^\\)]*\\+[^\\)]*\\)\\+", // Complex nested quantifiers
            };
            
            for (String suspiciousPattern : suspiciousPatterns) {
                if (regex.matches(".*" + suspiciousPattern + ".*")) {
                    return true;
                }
            }
            
            // Check for excessive nested quantifiers
            int quantifierCount = 0;
            for (char c : regex.toCharArray()) {
                if (c == '*' || c == '+' || c == '?') {
                    quantifierCount++;
                }
            }
            
            return quantifierCount > 10; // Arbitrary limit for safety
        }
    }
    
    /**
     * Data structure for discovery results
     */
    public static class DiscoveryResult {
        private final Set<String> defaultObjects;
        private final Set<String> customObjects;
        private final int totalCount;
        
        public DiscoveryResult(Set<String> defaultObjects, Set<String> customObjects) {
            this.defaultObjects = new HashSet<>(defaultObjects);
            this.customObjects = new HashSet<>(customObjects);
            this.totalCount = defaultObjects.size() + customObjects.size();
        }
        
        public Set<String> getDefaultObjects() { return defaultObjects; }
        public Set<String> getCustomObjects() { return customObjects; }
        public Set<String> getAllObjects() {
            Set<String> allObjects = new HashSet<>(defaultObjects);
            allObjects.addAll(customObjects);
            return allObjects;
        }
        public int getTotalCount() { return totalCount; }
        public int getDefaultCount() { return defaultObjects.size(); }
        public int getCustomCount() { return customObjects.size(); }
    }
    
    /**
     * Data structure for object by name search results
     */
    public static class ObjectByNameResult {
        private final java.util.Map<String, String> objectEntries;
        private final int totalCount;
        
        public ObjectByNameResult() {
            this.objectEntries = new java.util.LinkedHashMap<>();
            this.totalCount = 0;
        }
        
        public ObjectByNameResult(java.util.Map<String, String> objectEntries) {
            this.objectEntries = new java.util.LinkedHashMap<>(objectEntries);
            this.totalCount = objectEntries.size();
        }
        
        public java.util.Map<String, String> getObjectEntries() { return objectEntries; }
        public java.util.Set<String> getObjectNames() { return objectEntries.keySet(); }
        public String getObjectData(String objectName) { return objectEntries.get(objectName); }
        public int getTotalCount() { return totalCount; }
        
        public void addObjectEntry(String objectName, String jsonData) {
            objectEntries.put(objectName, jsonData);
        }
    }
    
    /**
     * Callback interface for result tab creation
     */
    public interface ResultTabCallback {
        void createResultTab(String resultId, String content);
        void createDiscoveryResultTab(String resultId, DiscoveryResult discoveryResult);
        void createObjectByNameTab(String resultId, ObjectByNameResult objectByNameResult);
        
        // New method for updating tabs without automatic switching
        default void updateObjectByNameTab(String resultId, ObjectByNameResult objectByNameResult) {
            // Default implementation falls back to createObjectByNameTab
            createObjectByNameTab(resultId, objectByNameResult);
        }
    }
    
    private final MontoyaApi api;
    private final List<BaseRequest> baseRequests;
    private final JPanel mainPanel;
    private final ResultTabCallback resultTabCallback;
    private final JComboBox<RequestItem> requestSelector;
    private final JButton findAllObjectNamesBtn;
    private final JButton findDefaultObjectsBtn;
    private final JButton findCustomObjectsBtn;
    private final JButton findAllObjectsBtn;
    private final JButton findObjectByNameBtn;
    private final JTextField objectNameField;
    private final JSpinner threadCountSpinner;
    private final JButton findDefaultObjectsPresetBtn;
    private final JButton selectWordlistBtn;
    private final JCheckBox usePresetWordlistCheckbox;
    private final JComboBox<String> discoveryResultSelector;
    private final JLabel statusMessageLabel;
    private final JPanel statusPanel;
    private File selectedWordlistFile;
    private boolean hasDiscoveryResults = false; // Track if discovery has been performed
    
    // State management fields
    private boolean isProcessing = false;
    private JButton currentActiveButton = null;
    private String originalButtonText = "";
    private final JButton cancelBtn;
    
    // Result tracking fields
    private int discoverResultCounter = 0;
    private int objByNameResultCounter = 0;
    private int objsByWordlistResultCounter = 0;
    private int retrievedObjectsResultCounter = 0;
    private final List<String> availableDiscoveryResults = new ArrayList<>();
    
    // Progress tracking fields for bulk retrieval
    private int totalObjectsToRetrieve = 0;
    private int objectsRetrieved = 0;
    private String currentBulkRetrievalTabId = null;
    private JLabel progressLabel;
    private Thread currentOperationThread = null;
    private volatile boolean operationCancelled = false;
    
    // Object storage for discovered objects
    private final Set<String> discoveredDefaultObjects = new HashSet<>();
    private final Set<String> discoveredCustomObjects = new HashSet<>();
    
    // Object by name results storage
    private ObjectByNameResult objectByNameResults = new ObjectByNameResult();
    private final Map<String, ObjectByNameResult> tabObjectResults = new HashMap<>();
    
    // Object discovery payload
    private static final String DISCOVERY_PAYLOAD = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{}}]}";
    
    // Specific object search payload template - %s will be replaced with the escaped object name
    private static final String SPECIFIC_OBJECT_PAYLOAD_TEMPLATE = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"entityNameOrId\":\"%s\",\"layoutType\":\"FULL\",\"pageSize\":1000,\"currentPage\":0,\"useTimeout\":false,\"getCount\":false,\"enableRowActions\":false}}]}";
    
    public ActionsTab(MontoyaApi api, List<BaseRequest> baseRequests, ResultTabCallback resultTabCallback) {
        this.api = api;
        this.baseRequests = baseRequests;
        this.resultTabCallback = resultTabCallback;
        
        // Create main panel
        this.mainPanel = new JPanel(new BorderLayout());
        
        // Initialize components
        this.requestSelector = new JComboBox<>();
        this.findAllObjectNamesBtn = new JButton("Discover Objects");
        this.findDefaultObjectsBtn = new JButton("Analyze Default Objects");
        this.findCustomObjectsBtn = new JButton("Analyze Custom Objects");
        this.findAllObjectsBtn = new JButton("Analyze All Objects");
        this.findObjectByNameBtn = new JButton("Find by Name");
        this.objectNameField = new JTextField(15);
        this.threadCountSpinner = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
        this.findDefaultObjectsPresetBtn = new JButton("Scan with Wordlist");
        this.selectWordlistBtn = new JButton("Choose File...");
        this.usePresetWordlistCheckbox = new JCheckBox("Use built-in wordlist", true);
        this.cancelBtn = new JButton("Cancel");
        this.discoveryResultSelector = new JComboBox<>();
        
        // Status panel for non-blocking feedback
        this.statusMessageLabel = new JLabel(" ");
        this.statusPanel = new JPanel(new BorderLayout());
        setupStatusPanel();
        
        setupUI();
        setupEventHandlers();
        
        // Initialize UI state based on current requests
        updateUIForRequestAvailability(!baseRequests.isEmpty());
    }
    
    private void setupUI() {
        // Top panel with request selector - more compact
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Target Request"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        topPanel.add(new JLabel("Request:"));
        requestSelector.setPreferredSize(new Dimension(400, 25));
        topPanel.add(requestSelector);
        
        // Main actions panel with grid layout for better organization
        JPanel actionsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        
        // Object Discovery section
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        JLabel discoveryLabel = new JLabel("Object Discovery");
        discoveryLabel.setFont(discoveryLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(discoveryLabel, gbc);
        
        gbc.gridy++; gbc.gridwidth = 1;
        findAllObjectNamesBtn.setText("Discover Objects");
        findAllObjectNamesBtn.setToolTipText("Find all available object names in the org (sends 1 request)");
        actionsPanel.add(findAllObjectNamesBtn, gbc);
        
        // Object Analysis section
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JLabel analysisLabel = new JLabel("Get Objects");
        analysisLabel.setFont(analysisLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(analysisLabel, gbc);
        
        // Discovery result selector
        gbc.gridy++; gbc.gridwidth = 2; gbc.gridx = 0;
        JPanel discoverySelectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        discoverySelectionPanel.add(new JLabel("Use discovery result:"));
        discoveryResultSelector.setPreferredSize(new Dimension(200, 25));
        discoveryResultSelector.setToolTipText("Select which discovery result to use for object retrieval");
        discoverySelectionPanel.add(discoveryResultSelector);
        actionsPanel.add(discoverySelectionPanel, gbc);
        
        gbc.gridy++; gbc.gridwidth = 1; gbc.gridx = 0;
        findDefaultObjectsBtn.setText("Get Default Objects");
        findDefaultObjectsBtn.setToolTipText("Get default Salesforce objects from discovery results (sends multiple requests)");
        actionsPanel.add(findDefaultObjectsBtn, gbc);
        
        gbc.gridx = 1;
        findCustomObjectsBtn.setText("Get Custom Objects");
        findCustomObjectsBtn.setToolTipText("Get custom objects from discovery results (sends multiple requests)");
        actionsPanel.add(findCustomObjectsBtn, gbc);
        
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        findAllObjectsBtn.setText("Get All Objects");
        findAllObjectsBtn.setToolTipText("Get all objects from discovery results (sends multiple requests)");
        actionsPanel.add(findAllObjectsBtn, gbc);
        
        // Targeted Search section
        gbc.gridy++; gbc.gridwidth = 2;
        JLabel targetedLabel = new JLabel("Get a Specific Object");
        targetedLabel.setFont(targetedLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(targetedLabel, gbc);
        
        gbc.gridy++; gbc.gridwidth = 1; gbc.gridx = 0;
        findObjectByNameBtn.setText("Get Object by Name");
        findObjectByNameBtn.setToolTipText("Get a specific object by name (sends 1 request)");
        actionsPanel.add(findObjectByNameBtn, gbc);
        
        gbc.gridx = 1;
        objectNameField.setPreferredSize(new Dimension(200, 25));
        objectNameField.setToolTipText("Enter the object name to search for");
        actionsPanel.add(objectNameField, gbc);
        
        // Wordlist Scanning section
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JLabel wordlistLabel = new JLabel("Get Objects Using a Predefined Wordlist");
        wordlistLabel.setFont(wordlistLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(wordlistLabel, gbc);
        
        gbc.gridy++; gbc.gridwidth = 2;
        findDefaultObjectsPresetBtn.setText("Get Objects with Wordlist");
        findDefaultObjectsPresetBtn.setToolTipText("Get objects using wordlist (sends multiple requests)");
        actionsPanel.add(findDefaultObjectsPresetBtn, gbc);
        
        // Wordlist options in a compact panel
        JPanel wordlistOptionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        usePresetWordlistCheckbox.setText("Use built-in wordlist");
        usePresetWordlistCheckbox.setToolTipText("Use the built-in Salesforce standard objects wordlist");
        wordlistOptionsPanel.add(usePresetWordlistCheckbox);
        
        selectWordlistBtn.setText("Choose File...");
        selectWordlistBtn.setToolTipText("Select a custom wordlist file");
        selectWordlistBtn.setPreferredSize(new Dimension(100, 25));
        wordlistOptionsPanel.add(selectWordlistBtn);
        
        gbc.gridy++;
        actionsPanel.add(wordlistOptionsPanel, gbc);
        
        // Thread count configuration
        gbc.gridy++; gbc.gridwidth = 2; gbc.weighty = 0.0;
        JPanel threadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        threadPanel.add(new JLabel("Concurrent requests:"));
        threadCountSpinner.setPreferredSize(new Dimension(60, 25));
        threadCountSpinner.setToolTipText("Number of concurrent requests for bulk operations (1-10)");
        threadPanel.add(threadCountSpinner);
        threadPanel.add(new JLabel("(reduces server load with lower values)"));
        actionsPanel.add(threadPanel, gbc);
        
        // Add some spacing at the bottom
        gbc.gridy++; gbc.weighty = 1.0;
        actionsPanel.add(Box.createVerticalGlue(), gbc);
        
        // Wrap in a panel with padding and left-align everything
        JPanel paddedPanel = new JPanel(new BorderLayout());
        paddedPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create a left-aligned wrapper
        JPanel leftAlignedWrapper = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        leftAlignedWrapper.add(actionsPanel);
        paddedPanel.add(leftAlignedWrapper, BorderLayout.WEST);
        
        // Add to main panel
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(paddedPanel, BorderLayout.CENTER);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
        
        // Initially disable wordlist file selection
        selectWordlistBtn.setEnabled(false);
        
        // Initialize discovery result selector
        discoveryResultSelector.setEnabled(false); // Will be enabled when discovery results are available
    }
    
    private void setupStatusPanel() {
        statusPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Status"),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        
        // Create top panel for status message and progress
        JPanel topPanel = new JPanel(new BorderLayout());
        statusMessageLabel.setFont(statusMessageLabel.getFont().deriveFont(Font.BOLD));
        topPanel.add(statusMessageLabel, BorderLayout.WEST);
        
        // Create progress label (initially hidden)
        progressLabel = new JLabel();
        progressLabel.setFont(progressLabel.getFont().deriveFont(Font.BOLD));
        progressLabel.setVisible(false);
        topPanel.add(progressLabel, BorderLayout.EAST);
        
        statusPanel.add(topPanel, BorderLayout.NORTH);
        
        // Create bottom panel for cancel button (centered)
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        cancelBtn.setPreferredSize(new Dimension(100, 30));
        cancelBtn.setVisible(false);
        bottomPanel.add(cancelBtn);
        
        statusPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        clearStatusMessage();
    }
    
    private void showStatusMessage(String message, Color color) {
        statusMessageLabel.setText(message);
        statusMessageLabel.setForeground(color);
        
        // Auto-clear informational and success messages
        if (color.equals(Color.BLUE) || color.equals(Color.GREEN)) {
            Timer timer = new Timer(5000, e -> clearStatusMessage());
            timer.setRepeats(false);
            timer.start();
        }
    }
    
    private void showErrorMessage(String message) {
        // Use default color with bold font for better dark mode visibility
        statusMessageLabel.setText("⚠ " + message);
        statusMessageLabel.setForeground(UIManager.getColor("Label.foreground")); // Default system color
        statusMessageLabel.setFont(statusMessageLabel.getFont().deriveFont(Font.BOLD));
        // No auto-clear for error messages
    }
    
    private void clearStatusMessage() {
        statusMessageLabel.setText(" ");
        statusMessageLabel.setForeground(UIManager.getColor("Label.foreground"));
        // Reset to normal font weight
        statusMessageLabel.setFont(statusMessageLabel.getFont().deriveFont(Font.PLAIN));
    }
    
    /**
     * Set busy state - disable all action buttons and show busy indicator
     */
    private void setBusyState(JButton activeButton, String operationName) {
        isProcessing = true;
        currentActiveButton = activeButton;
        originalButtonText = activeButton.getText();
        
        // Update active button to show it's working
        activeButton.setText("⟳ " + originalButtonText);
        activeButton.setEnabled(false);
        
        // Disable all other action buttons
        findAllObjectNamesBtn.setEnabled(false);
        findDefaultObjectsBtn.setEnabled(false);
        findCustomObjectsBtn.setEnabled(false);
        findAllObjectsBtn.setEnabled(false);
        findObjectByNameBtn.setEnabled(false);
        findDefaultObjectsPresetBtn.setEnabled(false);
        
        // Show busy status and cancel button
        showStatusMessage("⟳ " + operationName + " in progress...", Color.BLUE);
        cancelBtn.setVisible(true);
        
        // Hide progress for non-bulk operations
        progressLabel.setVisible(false);
        
        statusPanel.revalidate();
        statusPanel.repaint();
    }
    
    /**
     * Clear busy state - restore all buttons to normal state
     */
    private void clearBusyState() {
        isProcessing = false;
        
        // Restore active button
        if (currentActiveButton != null) {
            currentActiveButton.setText(originalButtonText);
            currentActiveButton = null;
            originalButtonText = "";
        }
        
        // Hide cancel button
        cancelBtn.setVisible(false);
        statusPanel.revalidate();
        statusPanel.repaint();
        
        // Re-enable buttons based on current state
        updateUIForRequestAvailability(!baseRequests.isEmpty());
        clearStatusMessage();
    }
    
    /**
     * Set busy state for bulk retrieval operations with progress tracking
     */
    private void setBulkRetrievalBusyState(JButton activeButton, String operationName, int totalObjects, String tabId) {
        setBusyState(activeButton, operationName);
        
        // Initialize progress tracking
        totalObjectsToRetrieve = totalObjects;
        objectsRetrieved = 0;
        currentBulkRetrievalTabId = tabId;
        operationCancelled = false; // Reset cancellation flag for new operation
        
        // Show progress indicator
        updateProgressDisplay();
        progressLabel.setVisible(true);
        
        statusPanel.revalidate();
        statusPanel.repaint();
    }
    
    /**
     * Update progress display for bulk retrieval
     */
    private void updateProgressDisplay() {
        if (totalObjectsToRetrieve > 0) {
            int percentage = (int) ((objectsRetrieved * 100.0) / totalObjectsToRetrieve);
            progressLabel.setText(String.format("%d%% (%d/%d)", percentage, objectsRetrieved, totalObjectsToRetrieve));
        }
    }
    
    /**
     * Clear bulk retrieval state
     */
    private void clearBulkRetrievalState() {
        totalObjectsToRetrieve = 0;
        objectsRetrieved = 0;
        currentBulkRetrievalTabId = null;
        operationCancelled = false; // Reset cancellation flag
        progressLabel.setVisible(false);
        clearBusyState();
    }
    
    /**
     * Generate result ID for discovery operations
     */
    private String generateDiscoverResultId(int requestId) {
        discoverResultCounter++;
        return "Discovered Objects " + discoverResultCounter + " - Req " + requestId;
    }
    
    /**
     * Generate result ID for object by name operations
     */
    private String generateObjByNameResultId(int requestId) {
        objByNameResultCounter++;
        return "ObjByName-Request" + requestId + "-" + objByNameResultCounter;
    }
    
    /**
     * Generate result ID for objects by wordlist operations
     */
    private String generateObjsByWordlistResultId(int requestId) {
        objsByWordlistResultCounter++;
        return "ObjsByWordList-Request" + requestId + "-" + objsByWordlistResultCounter;
    }
    
    /**
     * Generate result ID for retrieved objects operations
     */
    private String generateRetrievedObjectsResultId() {
        retrievedObjectsResultCounter++;
        return "Retrieved Objects " + retrievedObjectsResultCounter;
    }
    
    /**
     * Get user's choice for tab handling when adding to existing retrieved objects
     */
    private String getUserTabChoice() {
        // Check if there are existing retrieved objects tabs
        String lastTabId = "Retrieved Objects " + retrievedObjectsResultCounter;
        
        // Show dialog asking user preference
        Object[] options = {"Append to current tab (" + lastTabId + ")", "Create new tab"};
        int choice = JOptionPane.showOptionDialog(
            mainPanel,
            "You already have retrieved objects. How would you like to proceed?",
            "Tab Selection",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]
        );
        
        if (choice == 0) {
            // Append to existing tab
            return lastTabId;
        } else {
            // Create new tab and reset object results
            objectByNameResults = new ObjectByNameResult();
            return generateRetrievedObjectsResultId();
        }
    }
    
    /**
     * Get user's choice for tab handling when performing bulk retrieval
     */
    private String getUserTabChoiceForBulkRetrieval(String objectType, int objectCount) {
        // Check if there are existing retrieved objects tabs (use counter instead of current data)
        boolean hasExistingTabs = retrievedObjectsResultCounter > 0;

        // Always show dialog asking user preference
        String lastTabId = "Retrieved Objects " + retrievedObjectsResultCounter;
        Object[] options;
        String message;

        if (hasExistingTabs) {
            options = new Object[]{
                "Append to current tab (" + lastTabId + ")",
                "Create new tab",
                "Cancel"
            };
            String countText = objectCount > 0 ? objectCount + " " : "";
            message = "You are about to retrieve " + countText + objectType + ".\n" +
                     "You already have retrieved objects. How would you like to proceed?";
        } else {
            options = new Object[]{
                "Create new tab",
                "Cancel"
            };
            String countText = objectCount > 0 ? objectCount + " " : "";
            message = "You are about to retrieve " + countText + objectType + ".\n" +
                     "How would you like to proceed?";
        }
        
        int choice = JOptionPane.showOptionDialog(
            mainPanel,
            message,
            "Bulk Retrieval - Tab Selection",
            JOptionPane.YES_NO_CANCEL_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[0]
        );
        
        if (hasExistingTabs) {
            switch (choice) {
                case 0: // Append to existing tab
                    // Load existing results from the tab to preserve contents
                    ObjectByNameResult existingResults = tabObjectResults.get(lastTabId);
                    if (existingResults != null) {
                        objectByNameResults = existingResults; // Use existing results for appending
                    }
                    return lastTabId;
                case 1: // Create new tab
                    objectByNameResults = new ObjectByNameResult();
                    return generateRetrievedObjectsResultId();
                default: // Cancel or close
                    return null;
            }
        } else {
            switch (choice) {
                case 0: // Create new tab (only option)
                    objectByNameResults = new ObjectByNameResult();
                    return generateRetrievedObjectsResultId();
                default: // Cancel or close
                    return null;
            }
        }
    }
    
    /**
     * Add a discovery result to the available results list
     */
    private void addDiscoveryResult(String resultId) {
        availableDiscoveryResults.add(resultId);
        discoveryResultSelector.addItem(resultId);
        
        // Enable discovery result selector and select the new item
        discoveryResultSelector.setEnabled(true);
        discoveryResultSelector.setSelectedIndex(discoveryResultSelector.getItemCount() - 1);
    }
    
    /**
     * Get the currently selected discovery result
     */
    private String getSelectedDiscoveryResult() {
        return (String) discoveryResultSelector.getSelectedItem();
    }
    
    /**
     * Perform actual object discovery by modifying the request and parsing the response
     */
    private void performObjectDiscovery(BaseRequest baseRequest, String resultId) {
        api.logging().logToOutput("Starting object discovery with payload modification...");
        
        try {
            // Create a modified request with the discovery payload in the message parameter
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();
            HttpRequest discoveryRequest = modifyMessageParameter(originalRequest, DISCOVERY_PAYLOAD);
            
            // Send the request
            api.logging().logToOutput("Sending discovery request to: " + originalRequest.url());
            HttpRequestResponse response = api.http().sendRequest(discoveryRequest);
            
            if (response.response() == null) {
                throw new RuntimeException("No response received");
            }
            
            // Parse the response to extract object names
            String responseBody = response.response().bodyToString();
            api.logging().logToOutput("Discovery response received, parsing objects...");
            
            parseDiscoveryResponse(responseBody, resultId);
            
        } catch (Exception e) {
            api.logging().logToError("Object discovery failed: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Perform specific object search by modifying the request and parsing the response
     */
    private void performSpecificObjectSearch(BaseRequest baseRequest, String resultId, String objectName) {
        api.logging().logToOutput("Starting specific object search for: " + objectName);
        
        try {
            // Escape the object name for JSON
            String escapedObjectName = objectName.replace("\\", "\\\\").replace("\"", "\\\"");
            
            // Create the specific object payload with the escaped object name
            String specificObjectPayload = String.format(SPECIFIC_OBJECT_PAYLOAD_TEMPLATE, escapedObjectName);
            
            // Create a modified request with the specific object payload in the message parameter
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();
            HttpRequest specificObjectRequest = modifyMessageParameter(originalRequest, specificObjectPayload);
            
            // Send the request
            api.logging().logToOutput("Sending specific object request to: " + originalRequest.url());
            HttpRequestResponse response = api.http().sendRequest(specificObjectRequest);
            
            if (response.response() == null) {
                throw new RuntimeException("No response received");
            }
            
            // Parse the response to extract object data
            String responseBody = response.response().bodyToString();
            api.logging().logToOutput("Specific object response received, parsing data...");
            
            // Pass the request ID to the parser
            parseSpecificObjectResponse(responseBody, resultId, objectName, baseRequest.getId());
            
        } catch (Exception e) {
            api.logging().logToError("Specific object search failed: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * Perform bulk object retrieval with incremental results and progress tracking
     */
    private void performBulkObjectRetrieval(BaseRequest baseRequest, String tabId, Set<String> objectNames, String objectTypeDescription) {
        api.logging().logToOutput("Starting bulk object retrieval for " + objectNames.size() + " " + objectTypeDescription);
        
        // Create the tab immediately with in-progress indicator
        SwingUtilities.invokeLater(() -> {
            // Initialize the ObjectByNameResult for this tab
            tabObjectResults.put(tabId, new ObjectByNameResult());
            
            // Create the tab immediately with the final tab title
            // The tab content will be updated as objects are retrieved
            resultTabCallback.createObjectByNameTab(tabId, tabObjectResults.get(tabId));
        });
        
        int totalObjects = objectNames.size();
        final int[] successfulObjects = {0};
        
        try {
            for (String objectName : objectNames) {
                // Check if thread was interrupted (cancelled)
                if (Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Bulk object retrieval cancelled by user");
                    SwingUtilities.invokeLater(() -> {
                        clearBulkRetrievalState();
                        currentOperationThread = null; // Clear thread reference
                        
                        // Create tab with whatever data was collected so far
                        ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                        if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                            resultTabCallback.createObjectByNameTab(tabId, tabResult); // Use original tabId to update existing tab
                            showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                        } else {
                            showStatusMessage("Operation cancelled", Color.RED);
                        }
                    });
                    return;
                }
                
                try {
                    // Check for cancellation again before processing each object
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Bulk object retrieval cancelled during processing");
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null; // Clear thread reference

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                            } else {
                                showStatusMessage("Operation cancelled", Color.RED);
                            }
                        });
                        return;
                    }
                    
                    // Update progress tracking
                    objectsRetrieved++;
                    SwingUtilities.invokeLater(() -> {
                        updateProgressDisplay();
                        showStatusMessage("⟳ Retrieving " + objectTypeDescription + ": " + objectName, Color.BLUE);
                    });
                    
                    // Escape the object name for JSON
                    String escapedObjectName = objectName.replace("\\", "\\\\").replace("\"", "\\\"");
                    
                    // Create the specific object payload with the escaped object name
                    String specificObjectPayload = String.format(SPECIFIC_OBJECT_PAYLOAD_TEMPLATE, escapedObjectName);
                    
                    // Create a modified request with the specific object payload in the message parameter
                    HttpRequest originalRequest = baseRequest.getRequestResponse().request();
                    HttpRequest specificObjectRequest = modifyMessageParameter(originalRequest, specificObjectPayload);

                    // Check for cancellation BEFORE sending request (this is critical)
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Bulk object retrieval cancelled before sending request for: " + objectName);
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null;

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                            } else {
                                showStatusMessage("Operation cancelled", Color.RED);
                            }
                        });
                        return;
                    }

                    // Send the request
                    api.logging().logToOutput("Sending HTTP request for object: " + objectName);
                    HttpRequestResponse response = api.http().sendRequest(specificObjectRequest);
                    api.logging().logToOutput("HTTP request completed for object: " + objectName);
                    
                    // Check for cancellation after request
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Bulk object retrieval cancelled after request");
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null; // Clear thread reference

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                            } else {
                                showStatusMessage("Operation cancelled", Color.RED);
                            }
                        });
                        return;
                    }
                    
                    if (response.response() == null) {
                        api.logging().logToError("No response received for object: " + objectName);
                        continue;
                    }
                    
                    // Check for cancellation before parsing response
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Bulk object retrieval cancelled before parsing response");
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null; // Clear thread reference

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                            } else {
                                showStatusMessage("Operation cancelled", Color.RED);
                            }
                        });
                        return;
                    }

                    // Parse the response to extract object data
                    String responseBody = response.response().bodyToString();

                    // Parse and immediately add to tab using a modified parseSpecificObjectResponse
                    parseBulkObjectResponseIncremental(responseBody, tabId, objectName, baseRequest.getId());
                    successfulObjects[0]++;
                    
                    // Small delay to prevent overwhelming the server - adjusted based on thread count
                    try {
                        int threadCount = (Integer) threadCountSpinner.getValue();
                        int delayMs = Math.max(50, 200 / threadCount); // Faster with more "threads"
                        Thread.sleep(delayMs);
                    } catch (InterruptedException e) {
                        api.logging().logToOutput("Bulk object retrieval interrupted by user");
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null; // Clear thread reference
                            
                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult); // Use original tabId to update existing tab
                                showStatusMessage("Operation cancelled - " + successfulObjects[0] + " objects retrieved", Color.ORANGE);
                            } else {
                                showStatusMessage("Operation cancelled", Color.RED);
                            }
                        });
                        Thread.currentThread().interrupt(); // Preserve interrupt status
                        return;
                    }
                    
                } catch (Exception e) {
                    api.logging().logToError("Failed to retrieve object '" + objectName + "': " + e.getMessage());
                }
            }
            
            // Final update - remove in-progress indicator and show completion
            final int finalSuccessful = successfulObjects[0];
            final int finalTotal = totalObjects;
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                currentOperationThread = null; // Clear thread reference
                
                // Update tab title to remove "In Progress..." indicator
                resultTabCallback.createObjectByNameTab(tabId, tabObjectResults.get(tabId));
                
                // Show completion status
                Color statusColor = finalSuccessful == finalTotal ? Color.GREEN : Color.ORANGE;
                showStatusMessage("✓ Bulk retrieval completed: " + finalSuccessful + "/" + finalTotal + " " + objectTypeDescription + " - " + tabId, statusColor);
                
                api.logging().logToOutput("Bulk object retrieval completed:");
                api.logging().logToOutput("  Type: " + objectTypeDescription);
                api.logging().logToOutput("  Successful: " + finalSuccessful + "/" + finalTotal);
            });
            
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                currentOperationThread = null; // Clear thread reference
                showErrorMessage("Bulk retrieval failed: " + e.getMessage());
                api.logging().logToError("Bulk object retrieval failed: " + e.getMessage());
            });
        }
    }

    /**
     * Perform wordlist scanning with cancellation support and progress tracking
     */
    private void performWordlistScan(BaseRequest baseRequest, String tabId, String wordlistSource) {
        api.logging().logToOutput("Starting wordlist scan using: " + wordlistSource);

        // Load wordlist
        List<String> wordlist = new ArrayList<>();
        try {
            if (usePresetWordlistCheckbox.isSelected()) {
                // Load built-in wordlist from resources
                try (InputStream is = getClass().getResourceAsStream("/standard_objects.txt");
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            wordlist.add(line);
                        }
                    }
                }
            } else if (selectedWordlistFile != null) {
                // Load custom wordlist file
                try (BufferedReader reader = new BufferedReader(new FileReader(selectedWordlistFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            wordlist.add(line);
                        }
                    }
                }
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                showErrorMessage("Failed to load wordlist: " + e.getMessage());
                api.logging().logToError("Wordlist loading failed: " + e.getMessage());
            });
            return;
        }

        if (wordlist.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                showErrorMessage("Wordlist is empty or could not be loaded");
                api.logging().logToError("Empty or invalid wordlist");
            });
            return;
        }

        // Update progress tracking with total count
        totalObjectsToRetrieve = wordlist.size();
        objectsRetrieved = 0;
        SwingUtilities.invokeLater(() -> updateProgressDisplay());

        // Create the result tab immediately with in-progress indicator
        SwingUtilities.invokeLater(() -> {
            tabObjectResults.put(tabId, new ObjectByNameResult());
            resultTabCallback.createObjectByNameTab(tabId, tabObjectResults.get(tabId));
        });

        int totalWords = wordlist.size();
        final int[] successfulObjects = {0};
        final int[] foundObjects = {0};

        api.logging().logToOutput("Loaded " + totalWords + " words from " + wordlistSource);

        try {
            for (String objectName : wordlist) {
                // Check for cancellation before processing each word
                if (operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Wordlist scan cancelled during processing");
                    SwingUtilities.invokeLater(() -> {
                        clearBulkRetrievalState();
                        currentOperationThread = null;

                        // Create tab with whatever data was collected so far
                        ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                        if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                            resultTabCallback.createObjectByNameTab(tabId, tabResult);
                            showStatusMessage("Wordlist scan cancelled - " + foundObjects[0] + " objects found", Color.ORANGE);
                        } else {
                            showStatusMessage("Wordlist scan cancelled", Color.RED);
                        }
                    });
                    return;
                }

                try {
                    // Update progress tracking
                    objectsRetrieved++;
                    SwingUtilities.invokeLater(() -> {
                        updateProgressDisplay();
                        showStatusMessage("⟳ Scanning wordlist: " + objectName, Color.BLUE);
                    });

                    // Create a specific object request for this word
                    String escapedObjectName = objectName.replace("\\", "\\\\").replace("\"", "\\\"");
                    String specificObjectPayload = String.format(SPECIFIC_OBJECT_PAYLOAD_TEMPLATE, escapedObjectName);
                    HttpRequest originalRequest = baseRequest.getRequestResponse().request();
                    HttpRequest specificObjectRequest = modifyMessageParameter(originalRequest, specificObjectPayload);

                    // Check for cancellation BEFORE sending request (this is critical)
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Wordlist scan cancelled before sending request for: " + objectName);
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null;

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Wordlist scan cancelled - " + foundObjects[0] + " objects found", Color.ORANGE);
                            } else {
                                showStatusMessage("Wordlist scan cancelled", Color.RED);
                            }
                        });
                        return;
                    }

                    // Send the request
                    api.logging().logToOutput("Sending HTTP request for object: " + objectName);
                    HttpRequestResponse response = api.http().sendRequest(specificObjectRequest);
                    api.logging().logToOutput("HTTP request completed for object: " + objectName);

                    // Check for cancellation after request
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Wordlist scan cancelled after request");
                        return;
                    }

                    successfulObjects[0]++;

                    // Check for cancellation before parsing response
                    if (operationCancelled || Thread.currentThread().isInterrupted()) {
                        api.logging().logToOutput("Wordlist scan cancelled before parsing response");
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            currentOperationThread = null;

                            // Create tab with whatever data was collected so far
                            ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                            if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                showStatusMessage("Wordlist scan cancelled - " + foundObjects[0] + " objects found", Color.ORANGE);
                            } else {
                                showStatusMessage("Wordlist scan cancelled", Color.RED);
                            }
                        });
                        return;
                    }

                    // Parse response and check if object exists
                    String responseBody = response.response().bodyToString();
                    if (responseBody.contains("\"success\":true") && !responseBody.contains("INVALID_TYPE")) {
                        foundObjects[0]++;

                        // Parse and immediately add to tab
                        parseBulkObjectResponseIncremental(responseBody, tabId, objectName, baseRequest.getId());

                        api.logging().logToOutput("Found object: " + objectName);
                    }

                    // Add delay if configured
                    int delayMs = (Integer) threadCountSpinner.getValue() > 1 ? 100 : 200;
                    if (delayMs > 0) {
                        try {
                            Thread.sleep(delayMs);
                        } catch (InterruptedException e) {
                            api.logging().logToOutput("Wordlist scan interrupted during delay");
                            SwingUtilities.invokeLater(() -> {
                                clearBulkRetrievalState();
                                currentOperationThread = null;

                                // Create tab with whatever data was collected so far
                                ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                                if (tabResult != null && !tabResult.getObjectEntries().isEmpty()) {
                                    resultTabCallback.createObjectByNameTab(tabId, tabResult);
                                    showStatusMessage("Wordlist scan cancelled - " + foundObjects[0] + " objects found", Color.ORANGE);
                                } else {
                                    showStatusMessage("Wordlist scan cancelled", Color.RED);
                                }
                            });
                            Thread.currentThread().interrupt();
                            return;
                        }
                    }

                } catch (Exception e) {
                    api.logging().logToError("Failed to test object '" + objectName + "': " + e.getMessage());
                }
            }

            // Final update - show completion
            final int finalSuccessful = successfulObjects[0];
            final int finalFound = foundObjects[0];
            final int finalTotal = totalWords;
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                currentOperationThread = null;

                // Update tab title to remove "In Progress..." indicator
                resultTabCallback.createObjectByNameTab(tabId, tabObjectResults.get(tabId));

                // Show completion status
                Color statusColor = finalFound > 0 ? Color.GREEN : Color.ORANGE;
                showStatusMessage("✓ Wordlist scan completed: " + finalFound + " objects found (" + finalSuccessful + "/" + finalTotal + " tested) - " + tabId, statusColor);

                api.logging().logToOutput("Wordlist scan completed:");
                api.logging().logToOutput("  Source: " + wordlistSource);
                api.logging().logToOutput("  Tested: " + finalSuccessful + "/" + finalTotal);
                api.logging().logToOutput("  Found: " + finalFound + " objects");
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBulkRetrievalState();
                currentOperationThread = null;
                showErrorMessage("Wordlist scan failed: " + e.getMessage());
                api.logging().logToError("Wordlist scan failed: " + e.getMessage());
            });
        }
    }

    /**
     * Modify the message parameter in the request while preserving other parameters
     */
    private HttpRequest modifyMessageParameter(HttpRequest originalRequest, String messageValue) {
        String method = originalRequest.method();
        
        if ("GET".equalsIgnoreCase(method)) {
            // For GET requests, modify the message parameter in the URL
            return modifyUrlParameter(originalRequest, "message", messageValue);
        } else if ("POST".equalsIgnoreCase(method)) {
            // For POST requests, modify the message parameter in the body
            return modifyBodyParameter(originalRequest, "message", messageValue);
        } else {
            // For other methods, try body first, then URL
            try {
                return modifyBodyParameter(originalRequest, "message", messageValue);
            } catch (Exception e) {
                api.logging().logToOutput("Failed to modify body parameter, trying URL parameter");
                return modifyUrlParameter(originalRequest, "message", messageValue);
            }
        }
    }
    
    /**
     * Modify a parameter in the URL query string
     */
    private HttpRequest modifyUrlParameter(HttpRequest request, String paramName, String paramValue) {
        String originalUrl = request.url();
        
        try {
            // Parse the URL to extract query part
            String queryString = "";
            
            int queryIndex = originalUrl.indexOf('?');
            if (queryIndex != -1) {
                queryString = originalUrl.substring(queryIndex + 1);
            }
            
            // Parse existing parameters
            StringBuilder newQuery = new StringBuilder();
            boolean messageParamFound = false;
            
            if (!queryString.isEmpty()) {
                String[] params = queryString.split("&");
                for (String param : params) {
                    if (param.startsWith(paramName + "=")) {
                        // Replace the message parameter
                        if (newQuery.length() > 0) newQuery.append("&");
                        newQuery.append(paramName).append("=").append(java.net.URLEncoder.encode(paramValue, "UTF-8"));
                        messageParamFound = true;
                    } else {
                        // Keep other parameters unchanged
                        if (newQuery.length() > 0) newQuery.append("&");
                        newQuery.append(param);
                    }
                }
            }
            
            // Add message parameter if it wasn't found
            if (!messageParamFound) {
                if (newQuery.length() > 0) newQuery.append("&");
                newQuery.append(paramName).append("=").append(java.net.URLEncoder.encode(paramValue, "UTF-8"));
            }
            
            // Get the path from the original URL
            String fullPath = originalUrl.substring(originalUrl.indexOf('/', 8)); // Skip protocol and host
            String basePath;
            if (queryIndex != -1) {
                int pathQueryIndex = fullPath.indexOf('?');
                basePath = pathQueryIndex != -1 ? fullPath.substring(0, pathQueryIndex) : fullPath;
            } else {
                basePath = fullPath;
            }
            
            // Construct new path with query
            String newPath = basePath + "?" + newQuery.toString();
            api.logging().logToOutput("Modified URL parameter '" + paramName + "', new path: " + newPath);
            
            // Create new request with modified path
            return request.withPath(newPath);
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to modify URL parameter: " + e.getMessage(), e);
        }
    }
    
    /**
     * Modify a parameter in the POST body (form-encoded)
     */
    private HttpRequest modifyBodyParameter(HttpRequest request, String paramName, String paramValue) {
        String originalBody = request.bodyToString();
        
        try {
            // Parse existing parameters in the body
            StringBuilder newBody = new StringBuilder();
            boolean messageParamFound = false;
            
            if (!originalBody.isEmpty()) {
                String[] params = originalBody.split("&");
                for (String param : params) {
                    if (param.startsWith(paramName + "=")) {
                        // Replace the message parameter
                        if (newBody.length() > 0) newBody.append("&");
                        newBody.append(paramName).append("=").append(java.net.URLEncoder.encode(paramValue, "UTF-8"));
                        messageParamFound = true;
                    } else {
                        // Keep other parameters unchanged
                        if (newBody.length() > 0) newBody.append("&");
                        newBody.append(param);
                    }
                }
            }
            
            // Add message parameter if it wasn't found
            if (!messageParamFound) {
                if (newBody.length() > 0) newBody.append("&");
                newBody.append(paramName).append("=").append(java.net.URLEncoder.encode(paramValue, "UTF-8"));
            }
            
            return request.withBody(newBody.toString());
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to modify body parameter: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parse the discovery response to extract object names from apiNamesToKeyPrefixes
     */
    private void parseDiscoveryResponse(String responseBody, String resultId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);
            
            // Navigate to actions[0].returnValue.apiNamesToKeyPrefixes
            JsonNode actionsNode = rootNode.path("actions");
            if (!actionsNode.isArray() || actionsNode.size() == 0) {
                throw new RuntimeException("Invalid response format: no actions array");
            }
            
            JsonNode firstAction = actionsNode.get(0);
            String state = firstAction.path("state").asText();
            
            if (!"SUCCESS".equals(state)) {
                throw new RuntimeException("Discovery request failed with state: " + state);
            }
            
            JsonNode returnValue = firstAction.path("returnValue");
            JsonNode apiNamesNode = returnValue.path("apiNamesToKeyPrefixes");
            
            if (apiNamesNode.isMissingNode() || !apiNamesNode.isObject()) {
                throw new RuntimeException("No apiNamesToKeyPrefixes found in response");
            }
            
            // Clear previous discoveries for this session
            discoveredDefaultObjects.clear();
            discoveredCustomObjects.clear();
            
            // Extract object names and categorize them
            apiNamesNode.fieldNames().forEachRemaining(objectName -> {
                if (objectName.endsWith("__c")) {
                    discoveredCustomObjects.add(objectName);
                } else {
                    discoveredDefaultObjects.add(objectName);
                }
            });
            
            final int defaultCount = discoveredDefaultObjects.size();
            final int customCount = discoveredCustomObjects.size();
            
            // Create discovery result data structure
            DiscoveryResult discoveryResult = new DiscoveryResult(discoveredDefaultObjects, discoveredCustomObjects);
            
            // Update UI on EDT
            SwingUtilities.invokeLater(() -> {
                // Set discovery completion state
                hasDiscoveryResults = true;
                // Add to available discovery results
                addDiscoveryResult(resultId);
                clearBusyState();
                // Create result tab with structured discovery results
                resultTabCallback.createDiscoveryResultTab(resultId, discoveryResult);
                showStatusMessage("✓ Discovery completed: " + defaultCount + " default, " + customCount + " custom objects - " + resultId, Color.GREEN);
                
                api.logging().logToOutput("Object discovery completed successfully:");
                api.logging().logToOutput("  Default objects: " + defaultCount);
                api.logging().logToOutput("  Custom objects: " + customCount);
            });
            
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Failed to parse discovery response: " + e.getMessage());
            });
            throw new RuntimeException("Failed to parse discovery response", e);
        }
    }
    
    /**
     * Parse the specific object response to extract object data from result array
     */
    private void parseSpecificObjectResponse(String responseBody, String resultId, String objectName, int requestId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);
            
            // Navigate to actions[0].returnValue.result
            JsonNode actionsNode = rootNode.path("actions");
            if (!actionsNode.isArray() || actionsNode.size() == 0) {
                throw new RuntimeException("Invalid response format: no actions array");
            }
            
            JsonNode firstAction = actionsNode.get(0);
            String state = firstAction.path("state").asText();
            
            if (!"SUCCESS".equals(state)) {
                throw new RuntimeException("Specific object request failed with state: " + state);
            }
            
            JsonNode returnValue = firstAction.path("returnValue");
            JsonNode resultArray = returnValue.path("result");
            
            if (resultArray.isMissingNode() || !resultArray.isArray()) {
                throw new RuntimeException("No result array found in response");
            }
            
            // Get current timestamp for the request entry
            java.time.LocalDateTime now = java.time.LocalDateTime.now();
            java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String timestamp = now.format(formatter);
            
            // Create object entry name with request info
            String objectEntryName = objectName + " Object (request" + requestId + "-" + timestamp + ")";
            
            // Format the JSON result data
            String jsonData;
            if (resultArray.size() == 0) {
                jsonData = "No data found for object '" + objectName + "'\nResult: []";
            } else {
                StringBuilder jsonContent = new StringBuilder();
                jsonContent.append("Records found: ").append(resultArray.size()).append("\n\n");
                jsonContent.append("JSON Result Data:\n");
                jsonContent.append("──────────────────\n\n");
                
                // Pretty print the result array
                try {
                    jsonContent.append(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultArray));
                } catch (Exception e) {
                    // Fallback to raw JSON if pretty printing fails
                    jsonContent.append(resultArray.toString());
                }
                jsonData = jsonContent.toString();
            }
            
            // Add the object entry to the accumulated results
            objectByNameResults.addObjectEntry(objectEntryName, jsonData);
            
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                
                // Determine tab ID - ask user if this isn't the first object
                String tabId;
                if (objectByNameResults.getObjectEntries().size() == 1) {
                    // First object - create new tab
                    tabId = generateRetrievedObjectsResultId();
                } else {
                    // Ask user if they want to append or create new tab
                    tabId = getUserTabChoice();
                }
                
                // Use the new createObjectByNameTab method
                resultTabCallback.createObjectByNameTab(tabId, objectByNameResults);
                
                if (resultArray.size() == 0) {
                    showStatusMessage("✗ No results found for object '" + objectName + "' - " + tabId, Color.ORANGE);
                    api.logging().logToOutput("No data found for object: " + objectName);
                } else {
                    showStatusMessage("✓ Found " + resultArray.size() + " records for object '" + objectName + "' - " + tabId, Color.GREEN);
                    api.logging().logToOutput("Specific object search completed successfully:");
                    api.logging().logToOutput("  Object: " + objectName);
                    api.logging().logToOutput("  Records found: " + resultArray.size());
                }
            });
            
        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Failed to parse specific object response: " + e.getMessage());
            });
            throw new RuntimeException("Failed to parse specific object response", e);
        }
    }
    
    /**
     * Parse bulk object response incrementally and add to tab immediately
     */
    private void parseBulkObjectResponseIncremental(String responseBody, String tabId, String objectName, int requestId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);
            
            // Navigate to actions[0].returnValue.result
            JsonNode actionsNode = rootNode.path("actions");
            if (!actionsNode.isArray() || actionsNode.size() == 0) {
                api.logging().logToError("Invalid response format for object '" + objectName + "': no actions array");
                return;
            }
            
            JsonNode firstAction = actionsNode.get(0);
            String state = firstAction.path("state").asText();
            
            if (!"SUCCESS".equals(state)) {
                api.logging().logToError("Object request failed for '" + objectName + "' with state: " + state);
                return;
            }
            
            JsonNode returnValue = firstAction.path("returnValue");
            JsonNode resultArray = returnValue.path("result");
            
            if (resultArray.isMissingNode() || !resultArray.isArray()) {
                api.logging().logToError("No result array found for object: " + objectName);
                return;
            }
            
            // Get current timestamp for the request entry
            java.time.LocalDateTime now = java.time.LocalDateTime.now();
            java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String timestamp = now.format(formatter);
            
            // Create object entry name with request info
            String objectEntryName = objectName + " Object (request" + requestId + "-" + timestamp + ")";
            
            // Format the JSON result data
            String jsonData;
            if (resultArray.size() == 0) {
                jsonData = "No data found for object '" + objectName + "'\nResult: []";
            } else {
                StringBuilder jsonContent = new StringBuilder();
                jsonContent.append("Records found: ").append(resultArray.size()).append("\n\n");
                jsonContent.append("JSON Result Data:\n");
                jsonContent.append("──────────────────\n\n");
                
                // Pretty print the result array
                try {
                    jsonContent.append(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultArray));
                } catch (Exception e) {
                    // Fallback to raw JSON if pretty printing fails
                    jsonContent.append(resultArray.toString());
                }
                jsonData = jsonContent.toString();
            }
            
            // Add the object entry to the tab's ObjectByNameResult and update the tab
            SwingUtilities.invokeLater(() -> {
                ObjectByNameResult tabResult = tabObjectResults.get(tabId);
                if (tabResult != null) {
                    tabResult.addObjectEntry(objectEntryName, jsonData);
                    // Update the tab content without automatic switching (for incremental updates)
                    resultTabCallback.updateObjectByNameTab(tabId, tabResult);
                }
            });
            
        } catch (Exception e) {
            api.logging().logToError("Failed to parse object response for '" + objectName + "': " + e.getMessage());
        }
    }
    
    /**
     * Parse the bulk object response and accumulate results
     */
    private void parseBulkObjectResponse(String responseBody, String resultId, String objectName, int requestId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);
            
            // Navigate to actions[0].returnValue.result
            JsonNode actionsNode = rootNode.path("actions");
            if (!actionsNode.isArray() || actionsNode.size() == 0) {
                api.logging().logToError("Invalid response format for object '" + objectName + "': no actions array");
                return;
            }
            
            JsonNode firstAction = actionsNode.get(0);
            String state = firstAction.path("state").asText();
            
            if (!"SUCCESS".equals(state)) {
                api.logging().logToError("Object request failed for '" + objectName + "' with state: " + state);
                return;
            }
            
            JsonNode returnValue = firstAction.path("returnValue");
            JsonNode resultArray = returnValue.path("result");
            
            if (resultArray.isMissingNode() || !resultArray.isArray()) {
                api.logging().logToError("No result array found for object '" + objectName + "'");
                return;
            }
            
            // Get current timestamp for the entry
            java.time.LocalDateTime now = java.time.LocalDateTime.now();
            java.time.format.DateTimeFormatter formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String timestamp = now.format(formatter);
            
            String objectEntryName = objectName + " Object (request" + requestId + "-" + timestamp + ")";
            String jsonData;
            
            if (resultArray.size() == 0) {
                // Empty result
                jsonData = "No data found for object '" + objectName + "'\nResult: []";
                api.logging().logToOutput("No data found for object: " + objectName);
            } else {
                // Object found - format the JSON result data
                StringBuilder jsonContent = new StringBuilder();
                jsonContent.append("Records found: ").append(resultArray.size()).append("\n\n");
                jsonContent.append("JSON Result Data:\n");
                jsonContent.append("──────────────────\n\n");
                
                // Pretty print the result array
                try {
                    jsonContent.append(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(resultArray));
                } catch (Exception e) {
                    // Fallback to raw JSON if pretty printing fails
                    jsonContent.append(resultArray.toString());
                }
                jsonData = jsonContent.toString();
                api.logging().logToOutput("Retrieved " + resultArray.size() + " records for object: " + objectName);
            }
            
            // Add the object entry to the accumulated results
            objectByNameResults.addObjectEntry(objectEntryName, jsonData);
            
        } catch (Exception e) {
            api.logging().logToError("Failed to parse bulk object response for '" + objectName + "': " + e.getMessage());
        }
    }
    
    private void setupEventHandlers() {
        // Wordlist checkbox handler
        usePresetWordlistCheckbox.addActionListener(e -> {
            boolean usePreset = usePresetWordlistCheckbox.isSelected();
            selectWordlistBtn.setEnabled(!usePreset && hasRequests());
            if (usePreset) {
                selectedWordlistFile = null;
            }
        });
        
        // Wordlist file selection handler
        selectWordlistBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.setDialogTitle("Select Wordlist File");
            
            int result = fileChooser.showOpenDialog(mainPanel);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedWordlistFile = fileChooser.getSelectedFile();
                // Show brief confirmation message (this will auto-clear)
                showStatusMessage("ℹ Custom wordlist selected: " + selectedWordlistFile.getName(), Color.BLUE);
            }
        });
        
        // Action button handlers
        findAllObjectNamesBtn.addActionListener(e -> executeAction("FindAllObjectNames"));
        findDefaultObjectsBtn.addActionListener(e -> executeAction("FindDefaultObjects"));
        findCustomObjectsBtn.addActionListener(e -> executeAction("FindCustomObjects"));
        findAllObjectsBtn.addActionListener(e -> executeAction("FindAllObjects"));
        findObjectByNameBtn.addActionListener(e -> executeAction("FindObjectByName"));
        findDefaultObjectsPresetBtn.addActionListener(e -> executeAction("FindDefaultObjectsPreset"));
        
        // Cancel button handler
        cancelBtn.addActionListener(e -> {
            api.logging().logToOutput("Operation cancelled by user - stopping all requests");
            operationCancelled = true; // Set cancellation flag immediately

            // More aggressive thread stopping
            if (currentOperationThread != null && currentOperationThread.isAlive()) {
                api.logging().logToOutput("Interrupting operation thread: " + currentOperationThread.getName());
                currentOperationThread.interrupt();

                // Try to wait briefly for graceful shutdown
                try {
                    currentOperationThread.join(100); // Wait max 100ms
                } catch (InterruptedException ignored) {
                    // Ignore interruption during join
                }

                // Force stop if still alive
                if (currentOperationThread.isAlive()) {
                    api.logging().logToOutput("Thread still alive after interrupt, clearing reference");
                }

                currentOperationThread = null; // Clear thread reference
            }

            clearBulkRetrievalState(); // Use bulk-specific clear method
            api.logging().logToOutput("Cancellation complete - no new requests should be sent");
        });
        
        // Add document listener to object name field to enable/disable button
        objectNameField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateObjectByNameButtonState();
            }
            
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateObjectByNameButtonState();
            }
            
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateObjectByNameButtonState();
            }
        });
    }
    
    private void executeAction(String actionType) {
        if (isProcessing) {
            return; // Ignore if already processing
        }
        
        RequestItem selectedItem = (RequestItem) requestSelector.getSelectedItem();
        if (selectedItem == null) {
            return;
        }
        
        BaseRequest selectedRequest = selectedItem.getBaseRequest();
        String objectName = objectNameField.getText().trim();
        
        // Log the action (placeholder for actual implementation)
        api.logging().logToOutput("Executing action: " + actionType + 
                                " on request ID: " + selectedRequest.getId());
        
        switch (actionType) {
            case "FindAllObjectNames":
                setBusyState(findAllObjectNamesBtn, "Object Discovery");
                // Generate result ID
                String discoverResultId = generateDiscoverResultId(selectedRequest.getId());
                
                // Perform object discovery in background thread
                new Thread(() -> {
                    try {
                        performObjectDiscovery(selectedRequest, discoverResultId);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during object discovery: " + e.getMessage());
                            api.logging().logToError("Object discovery failed: " + e.getMessage());
                        });
                    }
                }).start();
                break;
            case "FindDefaultObjects":
                String selectedDiscoveryResult = getSelectedDiscoveryResult();
                if (selectedDiscoveryResult == null) {
                    showErrorMessage("No discovery results available. Run Object Discovery first.");
                    return;
                }
                if (discoveredDefaultObjects.isEmpty()) {
                    showErrorMessage("No default objects found in selected discovery result.");
                    return;
                }
                // Ask user about tab choice before starting bulk retrieval
                String tabId = getUserTabChoiceForBulkRetrieval("default", discoveredDefaultObjects.size());
                if (tabId == null) {
                    return; // User cancelled
                }
                
                setBulkRetrievalBusyState(findDefaultObjectsBtn, "Getting Default Objects", discoveredDefaultObjects.size(), tabId);
                
                api.logging().logToOutput("Retrieving " + discoveredDefaultObjects.size() + " default objects from discovery result: " + selectedDiscoveryResult);
                
                // Perform bulk object retrieval in background thread
                currentOperationThread = new Thread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, tabId, discoveredDefaultObjects, "default objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during default objects retrieval: " + e.getMessage());
                            api.logging().logToError("Default objects retrieval failed: " + e.getMessage());
                        });
                    }
                });
                currentOperationThread.start();
                break;
            case "FindCustomObjects":
                selectedDiscoveryResult = getSelectedDiscoveryResult();
                if (selectedDiscoveryResult == null) {
                    showErrorMessage("No discovery results available. Run Object Discovery first.");
                    return;
                }
                if (discoveredCustomObjects.isEmpty()) {
                    showErrorMessage("No custom objects found in selected discovery result.");
                    return;
                }
                // Ask user about tab choice before starting bulk retrieval
                String customTabId = getUserTabChoiceForBulkRetrieval("custom", discoveredCustomObjects.size());
                if (customTabId == null) {
                    return; // User cancelled
                }
                
                setBulkRetrievalBusyState(findCustomObjectsBtn, "Getting Custom Objects", discoveredCustomObjects.size(), customTabId);
                
                api.logging().logToOutput("Retrieving " + discoveredCustomObjects.size() + " custom objects from discovery result: " + selectedDiscoveryResult);
                
                // Perform bulk object retrieval in background thread
                currentOperationThread = new Thread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, customTabId, discoveredCustomObjects, "custom objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during custom objects retrieval: " + e.getMessage());
                            api.logging().logToError("Custom objects retrieval failed: " + e.getMessage());
                        });
                    }
                });
                currentOperationThread.start();
                break;
            case "FindAllObjects":
                selectedDiscoveryResult = getSelectedDiscoveryResult();
                if (selectedDiscoveryResult == null) {
                    showErrorMessage("No discovery results available. Run Object Discovery first.");
                    return;
                }
                if (discoveredDefaultObjects.isEmpty() && discoveredCustomObjects.isEmpty()) {
                    showErrorMessage("No objects found in selected discovery result.");
                    return;
                }
                // Combine all discovered objects for bulk retrieval
                Set<String> allDiscoveredObjects = new HashSet<>();
                allDiscoveredObjects.addAll(discoveredDefaultObjects);
                allDiscoveredObjects.addAll(discoveredCustomObjects);
                
                // Ask user about tab choice before starting bulk retrieval
                String allTabId = getUserTabChoiceForBulkRetrieval("all", allDiscoveredObjects.size());
                if (allTabId == null) {
                    return; // User cancelled
                }
                
                setBulkRetrievalBusyState(findAllObjectsBtn, "Getting All Objects", allDiscoveredObjects.size(), allTabId);
                
                api.logging().logToOutput("Retrieving " + allDiscoveredObjects.size() + " objects (" + 
                    discoveredDefaultObjects.size() + " default, " + discoveredCustomObjects.size() + 
                    " custom) from discovery result: " + selectedDiscoveryResult);
                
                // Perform bulk object retrieval in background thread
                currentOperationThread = new Thread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, allTabId, allDiscoveredObjects, "all objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during all objects retrieval: " + e.getMessage());
                            api.logging().logToError("All objects retrieval failed: " + e.getMessage());
                        });
                    }
                });
                currentOperationThread.start();
                break;
            case "FindObjectByName":
                if (objectName.isEmpty()) {
                    showErrorMessage("Please enter an object name to search for.");
                    return;
                }
                setBusyState(findObjectByNameBtn, "Getting Object by Name");
                // Use fixed result ID for reusable Object by Name tab
                String objByNameResultId = "Object by Name";
                
                // Perform specific object search in background thread
                new Thread(() -> {
                    try {
                        performSpecificObjectSearch(selectedRequest, objByNameResultId, objectName);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during specific object search: " + e.getMessage());
                            api.logging().logToError("Specific object search failed: " + e.getMessage());
                        });
                    }
                }).start();
                break;
            case "FindDefaultObjectsPreset":
                if (!usePresetWordlistCheckbox.isSelected() && selectedWordlistFile == null) {
                    showErrorMessage("Please select a wordlist file or use the preset wordlist.");
                    return;
                }

                // Ask user about tab choice before starting wordlist scan
                String wordlistResultId = getUserTabChoiceForBulkRetrieval("wordlist objects", -1); // Unknown count
                if (wordlistResultId == null) {
                    return; // User cancelled
                }

                String wordlistSource = usePresetWordlistCheckbox.isSelected() ?
                    "preset wordlist" : selectedWordlistFile.getName();

                // Set up bulk retrieval state for wordlist scanning
                setBulkRetrievalBusyState(findDefaultObjectsPresetBtn, "Scanning with Wordlist", 0, wordlistResultId);

                api.logging().logToOutput("Starting wordlist scan using: " + wordlistSource);

                // Perform wordlist scanning in background thread
                currentOperationThread = new Thread(() -> {
                    try {
                        performWordlistScan(selectedRequest, wordlistResultId, wordlistSource);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            showErrorMessage("Error during wordlist scan: " + e.getMessage());
                            api.logging().logToError("Wordlist scan failed: " + e.getMessage());
                        });
                    }
                });
                currentOperationThread.start();
                break;
        }
    }
    
    public Component getComponent() {
        return mainPanel;
    }
    
    public void refreshRequests() {
        SwingUtilities.invokeLater(() -> {
            requestSelector.removeAllItems();
            
            for (BaseRequest request : baseRequests) {
                requestSelector.addItem(new RequestItem(request));
            }
            
            // Update UI based on whether requests are available
            boolean hasRequests = !baseRequests.isEmpty();
            updateUIForRequestAvailability(hasRequests);
            
            // Select first item by default if available
            if (requestSelector.getItemCount() > 0) {
                requestSelector.setSelectedIndex(0);
            }
        });
    }
    
    private void updateUIForRequestAvailability(boolean hasRequests) {
        // Enable/disable discovery button based on request availability
        findAllObjectNamesBtn.setEnabled(hasRequests);
        
        // Enable/disable get objects buttons based on discovery results AND request availability
        boolean canGetObjects = hasRequests && hasDiscoveryResults;
        findDefaultObjectsBtn.setEnabled(canGetObjects);
        findCustomObjectsBtn.setEnabled(canGetObjects);
        findAllObjectsBtn.setEnabled(canGetObjects);
        
        // Get by name depends on both having requests and non-empty text field
        updateObjectByNameButtonState();
        
        // Wordlist button only depends on having requests
        findDefaultObjectsPresetBtn.setEnabled(hasRequests);
        
        // Other UI elements
        objectNameField.setEnabled(hasRequests);
        requestSelector.setEnabled(hasRequests);
        usePresetWordlistCheckbox.setEnabled(hasRequests);
        selectWordlistBtn.setEnabled(hasRequests && !usePresetWordlistCheckbox.isSelected());
        
        if (!hasRequests) {
            // Show persistent error message when no requests are available
            showErrorMessage("At least one base request is needed. Add requests from the Base Requests tab.");
        } else {
            // Only clear message when requests become available
            clearStatusMessage();
        }
    }
    
    private void updateObjectByNameButtonState() {
        boolean hasRequests = !baseRequests.isEmpty();
        boolean hasText = !objectNameField.getText().trim().isEmpty();
        findObjectByNameBtn.setEnabled(hasRequests && hasText);
    }
    
    public boolean hasRequests() {
        return !baseRequests.isEmpty();
    }
    
    /**
     * Show empty state message when tab is accessed but no requests are available
     */
    public void showEmptyStateMessage() {
        // Trigger UI update to show disabled state and helpful message
        updateUIForRequestAvailability(false);
    }
    
    /**
     * Panel for displaying discovery results with categories menu and object list
     * Enhanced with search and filter functionality
     */
    public static class DiscoveryResultPanel extends JPanel {
        private final DiscoveryResult discoveryResult;
        private final JList<String> categoryList;
        private final JTextArea objectListArea;
        private final JSplitPane splitPane;
        
        // Search and filter components
        private JTextField searchField;
        private JTextField filterField;
        private JCheckBox searchRegexCheckBox;
        private JCheckBox filterRegexCheckBox;
        private JCheckBox hideEmptyCheckBox;
        private JButton searchNextBtn;
        private JButton searchPrevBtn;
        private JButton resetBtn;
        private JLabel searchStatusLabel;
        
        // Search state
        private int currentSearchIndex = -1;
        private List<Integer> searchMatches = new ArrayList<>();
        private String lastSearchText = "";
        
        // Filter state
        private DefaultListModel<String> originalCategoryModel;
        private DefaultListModel<String> filteredCategoryModel;
        private String[] originalCategories;
        private boolean isFiltered = false;
        
        public DiscoveryResultPanel(DiscoveryResult discoveryResult) {
            this.discoveryResult = discoveryResult;
            this.setLayout(new BorderLayout());
            
            // Store original categories
            this.originalCategories = new String[]{
                "Default Object Names (" + discoveryResult.getDefaultCount() + ")",
                "Custom Object Names (" + discoveryResult.getCustomCount() + ")",
                "All Object Names (" + discoveryResult.getTotalCount() + ")"
            };
            
            // Initialize list models
            this.originalCategoryModel = new DefaultListModel<>();
            this.filteredCategoryModel = new DefaultListModel<>();
            for (String category : originalCategories) {
                originalCategoryModel.addElement(category);
                filteredCategoryModel.addElement(category);
            }
            
            // Create toolbar with search and filter controls
            JPanel toolbar = createToolbar();
            this.add(toolbar, BorderLayout.NORTH);
            
            // Create category list (left panel)
            this.categoryList = new JList<>(originalCategoryModel);
            categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            categoryList.setSelectedIndex(0); // Select first item by default
            
            // Create object list area (right panel)
            this.objectListArea = new JTextArea();
            objectListArea.setEditable(false);
            objectListArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            
            // Add selection listener to update object list
            categoryList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    updateObjectList();
                    clearSearch(); // Clear search when changing categories
                }
            });
            
            // Create split pane
            JScrollPane categoryScrollPane = new JScrollPane(categoryList);
            categoryScrollPane.setPreferredSize(new Dimension(300, 0));
            
            JScrollPane objectScrollPane = new JScrollPane(objectListArea);
            
            this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, categoryScrollPane, objectScrollPane);
            splitPane.setDividerLocation(300);
            splitPane.setResizeWeight(0.3); // Give 30% to categories, 70% to object list
            
            this.add(splitPane, BorderLayout.CENTER);
            
            // Initialize with first category selected
            updateObjectList();
        }
        
        private JPanel createToolbar() {
            JPanel toolbar = new JPanel(new BorderLayout());
            toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            
            // Left panel: Search controls
            JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
            searchPanel.add(new JLabel("Search:"));
            
            this.searchField = new JTextField(15);
            searchPanel.add(searchField);
            
            this.searchRegexCheckBox = new JCheckBox("Regex");
            searchPanel.add(searchRegexCheckBox);
            
            this.searchNextBtn = new JButton("Next");
            this.searchPrevBtn = new JButton("Prev");
            searchPanel.add(searchNextBtn);
            searchPanel.add(searchPrevBtn);
            
            this.searchStatusLabel = new JLabel(" ");
            searchPanel.add(searchStatusLabel);
            
            // Center panel: Filter controls
            JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
            filterPanel.add(new JLabel("Filter:"));
            
            this.filterField = new JTextField(15);
            filterPanel.add(filterField);
            
            this.filterRegexCheckBox = new JCheckBox("Regex");
            filterPanel.add(filterRegexCheckBox);
            
            this.hideEmptyCheckBox = new JCheckBox("Hide Empty");
            filterPanel.add(hideEmptyCheckBox);
            
            // Right panel: Reset button
            JPanel resetPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
            this.resetBtn = new JButton("Reset/Show All");
            resetPanel.add(resetBtn);
            
            // Add panels to toolbar
            toolbar.add(searchPanel, BorderLayout.WEST);
            toolbar.add(filterPanel, BorderLayout.CENTER);
            toolbar.add(resetPanel, BorderLayout.EAST);
            
            // Add event listeners
            setupToolbarEventHandlers();
            
            return toolbar;
        }
        
        private void setupToolbarEventHandlers() {
            // Search field - trigger search on Enter or text change with delay
            searchField.addActionListener(e -> performSearch());
            
            javax.swing.Timer searchTimer = new javax.swing.Timer(500, e -> {
                if (!searchField.getText().equals(lastSearchText)) {
                    performSearch();
                }
            });
            searchTimer.setRepeats(false);
            
            searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
            });
            
            // Search navigation buttons
            searchNextBtn.addActionListener(e -> navigateSearch(true));
            searchPrevBtn.addActionListener(e -> navigateSearch(false));
            
            // Search regex checkbox
            searchRegexCheckBox.addActionListener(e -> performSearch());
            
            // Filter field - trigger filter on text change with delay
            javax.swing.Timer filterTimer = new javax.swing.Timer(300, e -> applyFilter());
            filterTimer.setRepeats(false);
            
            filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
            });
            
            // Filter regex checkbox
            filterRegexCheckBox.addActionListener(e -> applyFilter());
            
            // Hide empty checkbox
            hideEmptyCheckBox.addActionListener(e -> applyFilter());
            
            // Reset button
            resetBtn.addActionListener(e -> resetAllFilters());
        }
        
        private void performSearch() {
            String searchText = searchField.getText().trim();
            lastSearchText = searchText;
            
            if (searchText.isEmpty()) {
                clearSearch();
                return;
            }
            
            String objectText = objectListArea.getText();
            searchMatches.clear();
            currentSearchIndex = -1;
            
            if (objectText.isEmpty()) {
                updateSearchStatus("No content to search");
                return;
            }
            
            if (searchRegexCheckBox.isSelected()) {
                // Safe regex search with timeout protection
                try {
                    java.util.regex.Pattern pattern = SafeRegex.safeCompile(searchText, 
                        java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.MULTILINE);
                    
                    // Update status to show search is in progress
                    updateSearchStatus("Searching...");
                    
                    List<Integer> matches = SafeRegex.safeFind(pattern, objectText);
                    searchMatches.addAll(matches);
                    
                } catch (java.util.regex.PatternSyntaxException e) {
                    updateSearchStatus("Invalid regex: " + e.getDescription());
                    return;
                } catch (RuntimeException e) {
                    if (e.getMessage().contains("timed out")) {
                        updateSearchStatus("Search timed out - pattern too complex");
                    } else if (e.getMessage().contains("unsafe pattern")) {
                        updateSearchStatus("Unsafe pattern detected");
                    } else {
                        updateSearchStatus("Search error: " + e.getMessage());
                    }
                    return;
                }
            } else {
                // Plain text search (case insensitive) - safe and fast
                String lowerText = objectText.toLowerCase();
                String lowerSearch = searchText.toLowerCase();
                int index = 0;
                
                while ((index = lowerText.indexOf(lowerSearch, index)) != -1) {
                    searchMatches.add(index);
                    index++;
                    
                    // Prevent excessive matches that could slow down UI
                    if (searchMatches.size() > 10000) {
                        updateSearchStatus("Too many matches (>10000) - showing first 10000");
                        break;
                    }
                }
            }
            
            if (searchMatches.isEmpty()) {
                updateSearchStatus("Not found");
            } else {
                currentSearchIndex = 0;
                highlightCurrentMatch();
                updateSearchStatus((currentSearchIndex + 1) + " of " + searchMatches.size());
            }
        }
        
        private void navigateSearch(boolean next) {
            if (searchMatches.isEmpty()) {
                performSearch(); // Try to search if no matches yet
                return;
            }
            
            if (next) {
                currentSearchIndex = (currentSearchIndex + 1) % searchMatches.size();
            } else {
                currentSearchIndex = (currentSearchIndex - 1 + searchMatches.size()) % searchMatches.size();
            }
            
            highlightCurrentMatch();
            updateSearchStatus((currentSearchIndex + 1) + " of " + searchMatches.size());
        }
        
        private void highlightCurrentMatch() {
            if (currentSearchIndex >= 0 && currentSearchIndex < searchMatches.size()) {
                int start = searchMatches.get(currentSearchIndex);
                String searchText = searchField.getText();
                int length = searchText.length();
                
                // If regex, calculate actual match length safely
                if (searchRegexCheckBox.isSelected()) {
                    try {
                        java.util.regex.Pattern pattern = SafeRegex.safeCompile(searchText, 
                            java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.MULTILINE);
                        
                        // Create a small substring around the match to avoid processing entire text again
                        String fullText = objectListArea.getText();
                        int contextStart = Math.max(0, start - 100);
                        int contextEnd = Math.min(fullText.length(), start + searchText.length() + 100);
                        String contextText = fullText.substring(contextStart, contextEnd);
                        
                        java.util.regex.Matcher matcher = pattern.matcher(contextText);
                        int adjustedStart = start - contextStart;
                        
                        if (matcher.find(adjustedStart) && matcher.start() == adjustedStart) {
                            length = matcher.end() - matcher.start();
                        }
                    } catch (Exception e) {
                        // Fall back to search text length if regex processing fails
                    }
                }
                
                objectListArea.setSelectionStart(start);
                objectListArea.setSelectionEnd(start + length);
                objectListArea.getCaret().setSelectionVisible(true);
                
                // Scroll to make selection visible
                try {
                    objectListArea.scrollRectToVisible(objectListArea.modelToView2D(start).getBounds());
                } catch (Exception e) {
                    // Ignore scrolling errors
                }
            }
        }
        
        private void clearSearch() {
            searchMatches.clear();
            currentSearchIndex = -1;
            objectListArea.setSelectionStart(0);
            objectListArea.setSelectionEnd(0);
            updateSearchStatus(" ");
        }
        
        private void updateSearchStatus(String status) {
            searchStatusLabel.setText(status);
        }
        
        private void applyFilter() {
            String filterText = filterField.getText().trim();
            boolean useRegex = filterRegexCheckBox.isSelected();
            boolean hideEmpty = hideEmptyCheckBox.isSelected();
            
            filteredCategoryModel.clear();
            isFiltered = !filterText.isEmpty() || hideEmpty;
            
            for (int i = 0; i < originalCategories.length; i++) {
                String category = originalCategories[i];
                boolean includeCategory = true;
                
                // Check if category should be hidden due to empty content
                if (hideEmpty) {
                    Set<String> objects = getObjectsForCategoryIndex(i);
                    if (objects.isEmpty()) {
                        includeCategory = false;
                    }
                }
                
                // Check filter text against objects in this category
                if (includeCategory && !filterText.isEmpty()) {
                    Set<String> objects = getObjectsForCategoryIndex(i);
                    boolean hasMatchingObject = false;
                    
                    try {
                        if (useRegex) {
                            // Safe regex filtering with timeout protection
                            java.util.regex.Pattern pattern = SafeRegex.safeCompile(filterText, 
                                java.util.regex.Pattern.CASE_INSENSITIVE);
                            
                            for (String obj : objects) {
                                if (SafeRegex.safeMatches(pattern, obj)) {
                                    hasMatchingObject = true;
                                    break;
                                }
                            }
                        } else {
                            // Plain text filtering - safe and fast
                            String lowerFilter = filterText.toLowerCase();
                            for (String obj : objects) {
                                if (obj.toLowerCase().contains(lowerFilter)) {
                                    hasMatchingObject = true;
                                    break;
                                }
                            }
                        }
                    } catch (java.util.regex.PatternSyntaxException e) {
                        // Invalid regex, skip filtering and include category
                        hasMatchingObject = true;
                    } catch (RuntimeException e) {
                        // Timeout or other error, skip filtering and include category
                        hasMatchingObject = true;
                    }
                    
                    if (!hasMatchingObject) {
                        includeCategory = false;
                    }
                }
                
                if (includeCategory) {
                    filteredCategoryModel.addElement(category);
                }
            }
            
            // Update the list model
            categoryList.setModel(filteredCategoryModel);
            
            // Select first item if available
            if (filteredCategoryModel.getSize() > 0) {
                categoryList.setSelectedIndex(0);
            }
            
            // Update reset button state
            resetBtn.setEnabled(isFiltered);
        }
        
        private Set<String> getObjectsForCategoryIndex(int index) {
            switch (index) {
                case 0: return discoveryResult.getDefaultObjects();
                case 1: return discoveryResult.getCustomObjects();
                case 2: return discoveryResult.getAllObjects();
                default: return new HashSet<>();
            }
        }
        
        private void resetAllFilters() {
            searchField.setText("");
            filterField.setText("");
            hideEmptyCheckBox.setSelected(false);
            
            categoryList.setModel(originalCategoryModel);
            isFiltered = false;
            resetBtn.setEnabled(false);
            
            // Select first item
            if (originalCategoryModel.getSize() > 0) {
                categoryList.setSelectedIndex(0);
            }
            
            clearSearch();
        }
        
        private void updateObjectList() {
            String selectedCategory = categoryList.getSelectedValue();
            if (selectedCategory == null) return;
            
            // Find the original index of this category
            int originalIndex = -1;
            for (int i = 0; i < originalCategories.length; i++) {
                if (originalCategories[i].equals(selectedCategory)) {
                    originalIndex = i;
                    break;
                }
            }
            
            if (originalIndex == -1) return;
            
            Set<String> objects = getObjectsForCategoryIndex(originalIndex);
            
            // Sort and display objects, each on a new line
            StringBuilder content = new StringBuilder();
            objects.stream()
                    .sorted()
                    .forEach(obj -> content.append(obj).append("\n"));
            
            objectListArea.setText(content.toString());
            objectListArea.setCaretPosition(0); // Scroll to top
            
            // Clear search when content changes
            clearSearch();
        }
    }
    
    /**
     * Helper class to display requests in the combo box
     */
    private static class RequestItem {
        private final BaseRequest baseRequest;
        
        public RequestItem(BaseRequest baseRequest) {
            this.baseRequest = baseRequest;
        }
        
        public BaseRequest getBaseRequest() {
            return baseRequest;
        }
        
        @Override
        public String toString() {
            return "ID " + baseRequest.getId() + ": " + 
                   (baseRequest.getUrl().length() > 50 ? 
                    baseRequest.getUrl().substring(0, 50) + "..." : 
                    baseRequest.getUrl());
        }
    }
    
    /**
     * Panel for displaying object by name results with search/filter functionality
     * Similar style to DiscoveryResultPanel but shows object entries and their JSON data
     */
    public static class ObjectByNameResultPanel extends JPanel {
        private final ObjectByNameResult objectByNameResult;
        private final JList<String> objectList;
        private final JTextArea jsonDataArea;
        private final JSplitPane splitPane;
        
        // Search and filter components
        private JTextField searchField;
        private JTextField filterField;
        private JCheckBox searchRegexCheckBox;
        private JCheckBox filterRegexCheckBox;
        private JCheckBox hideEmptyCheckBox;
        private JButton searchNextBtn;
        private JButton searchPrevBtn;
        private JButton resetBtn;
        private JLabel searchStatusLabel;
        
        // Search state
        private int currentSearchIndex = -1;
        private List<Integer> searchMatches = new ArrayList<>();
        private String lastSearchText = "";
        
        // Filter state
        private DefaultListModel<String> originalObjectModel;
        private DefaultListModel<String> filteredObjectModel;
        
        public ObjectByNameResultPanel(ObjectByNameResult objectByNameResult) {
            this.objectByNameResult = objectByNameResult;
            this.setLayout(new BorderLayout());
            
            // Initialize list models
            this.originalObjectModel = new DefaultListModel<>();
            this.filteredObjectModel = new DefaultListModel<>();
            
            // Populate with object entries
            for (String objectName : objectByNameResult.getObjectNames()) {
                originalObjectModel.addElement(objectName);
                filteredObjectModel.addElement(objectName);
            }
            
            // Create toolbar with search and filter controls
            JPanel toolbar = createToolbar();
            this.add(toolbar, BorderLayout.NORTH);
            
            // Create object list (left panel)
            this.objectList = new JList<>(originalObjectModel);
            objectList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            if (originalObjectModel.getSize() > 0) {
                objectList.setSelectedIndex(0); // Select first item by default
            }
            
            // Create JSON data area (right panel)
            this.jsonDataArea = new JTextArea();
            jsonDataArea.setEditable(false);
            jsonDataArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            
            // Add selection listener to update JSON data
            objectList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    updateJsonData();
                    clearSearch(); // Clear search when changing selection
                }
            });
            
            // Create split pane
            JScrollPane objectScrollPane = new JScrollPane(objectList);
            objectScrollPane.setPreferredSize(new Dimension(400, 0));
            
            JScrollPane jsonScrollPane = new JScrollPane(jsonDataArea);
            
            this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, objectScrollPane, jsonScrollPane);
            splitPane.setDividerLocation(400);
            splitPane.setResizeWeight(0.4); // Give 40% to object list, 60% to JSON data
            
            this.add(splitPane, BorderLayout.CENTER);
            
            // Initialize with first object selected
            updateJsonData();
        }
        
        private JPanel createToolbar() {
            JPanel toolbar = new JPanel(new BorderLayout());
            toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            
            // Left panel: Search controls
            JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
            searchPanel.add(new JLabel("Search:"));
            
            this.searchField = new JTextField(15);
            searchPanel.add(searchField);
            
            this.searchRegexCheckBox = new JCheckBox("Regex");
            searchPanel.add(searchRegexCheckBox);
            
            this.searchNextBtn = new JButton("Next");
            this.searchPrevBtn = new JButton("Prev");
            searchPanel.add(searchNextBtn);
            searchPanel.add(searchPrevBtn);
            
            this.searchStatusLabel = new JLabel(" ");
            searchPanel.add(searchStatusLabel);
            
            // Center panel: Filter controls
            JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
            filterPanel.add(new JLabel("Filter:"));
            
            this.filterField = new JTextField(15);
            filterPanel.add(filterField);
            
            this.filterRegexCheckBox = new JCheckBox("Regex");
            filterPanel.add(filterRegexCheckBox);
            
            this.hideEmptyCheckBox = new JCheckBox("Hide Empty");
            filterPanel.add(hideEmptyCheckBox);
            
            // Right panel: Reset button
            JPanel resetPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
            this.resetBtn = new JButton("Reset/Show All");
            resetPanel.add(resetBtn);
            
            // Add panels to toolbar
            toolbar.add(searchPanel, BorderLayout.WEST);
            toolbar.add(filterPanel, BorderLayout.CENTER);
            toolbar.add(resetPanel, BorderLayout.EAST);
            
            // Add event listeners
            setupToolbarEventHandlers();
            
            return toolbar;
        }
        
        private void setupToolbarEventHandlers() {
            // Search field - trigger search on Enter or text change with delay
            searchField.addActionListener(e -> performSearch());
            
            javax.swing.Timer searchTimer = new javax.swing.Timer(500, e -> {
                if (!searchField.getText().equals(lastSearchText)) {
                    performSearch();
                }
            });
            searchTimer.setRepeats(false);
            
            searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    searchTimer.restart();
                }
            });
            
            // Search navigation buttons
            searchNextBtn.addActionListener(e -> navigateSearch(true));
            searchPrevBtn.addActionListener(e -> navigateSearch(false));
            
            // Search regex checkbox
            searchRegexCheckBox.addActionListener(e -> performSearch());
            
            // Filter field - trigger filter on text change with delay
            javax.swing.Timer filterTimer = new javax.swing.Timer(300, e -> applyFilter());
            filterTimer.setRepeats(false);
            
            filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                @Override
                public void insertUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
                @Override
                public void removeUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
                @Override
                public void changedUpdate(javax.swing.event.DocumentEvent e) {
                    filterTimer.restart();
                }
            });
            
            // Filter regex checkbox
            filterRegexCheckBox.addActionListener(e -> applyFilter());
            
            // Hide empty checkbox
            hideEmptyCheckBox.addActionListener(e -> applyFilter());
            
            // Reset button
            resetBtn.addActionListener(e -> resetAllFilters());
        }
        
        private void updateJsonData() {
            String selectedObject = objectList.getSelectedValue();
            if (selectedObject != null) {
                String jsonData = objectByNameResult.getObjectData(selectedObject);
                jsonDataArea.setText(jsonData != null ? jsonData : "No data available");
                jsonDataArea.setCaretPosition(0); // Scroll to top
            } else {
                jsonDataArea.setText("Select an object to view its data");
            }
        }
        
        private void performSearch() {
            String searchText = searchField.getText().trim();
            lastSearchText = searchText;
            
            if (searchText.isEmpty()) {
                clearSearch();
                return;
            }
            
            String jsonText = jsonDataArea.getText();
            searchMatches.clear();
            currentSearchIndex = -1;
            
            if (jsonText.isEmpty()) {
                updateSearchStatus("No content to search");
                return;
            }
            
            if (searchRegexCheckBox.isSelected()) {
                // Safe regex search with timeout protection
                try {
                    java.util.regex.Pattern pattern = SafeRegex.safeCompile(searchText, 
                        java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.MULTILINE);
                    
                    // Update status to show search is in progress
                    updateSearchStatus("Searching...");
                    
                    List<Integer> matches = SafeRegex.safeFind(pattern, jsonText);
                    searchMatches.addAll(matches);
                    
                } catch (java.util.regex.PatternSyntaxException e) {
                    updateSearchStatus("Invalid regex: " + e.getDescription());
                    return;
                } catch (RuntimeException e) {
                    if (e.getMessage().contains("timed out")) {
                        updateSearchStatus("Search timed out - pattern too complex");
                    } else if (e.getMessage().contains("unsafe pattern")) {
                        updateSearchStatus("Unsafe pattern detected");
                    } else {
                        updateSearchStatus("Search error: " + e.getMessage());
                    }
                    return;
                }
            } else {
                // Plain text search (case insensitive) - safe and fast
                String lowerText = jsonText.toLowerCase();
                String lowerSearch = searchText.toLowerCase();
                int index = 0;
                
                while ((index = lowerText.indexOf(lowerSearch, index)) != -1) {
                    searchMatches.add(index);
                    index++;
                    
                    // Prevent excessive matches that could slow down UI
                    if (searchMatches.size() > 10000) {
                        updateSearchStatus("Too many matches (>10000) - showing first 10000");
                        break;
                    }
                }
            }
            
            if (searchMatches.isEmpty()) {
                updateSearchStatus("Not found");
            } else {
                currentSearchIndex = 0;
                highlightCurrentMatch();
                updateSearchStatus((currentSearchIndex + 1) + " of " + searchMatches.size());
            }
        }
        
        private void navigateSearch(boolean forward) {
            if (searchMatches.isEmpty()) {
                updateSearchStatus("No search results");
                return;
            }
            
            if (forward) {
                currentSearchIndex = (currentSearchIndex + 1) % searchMatches.size();
            } else {
                currentSearchIndex = (currentSearchIndex - 1 + searchMatches.size()) % searchMatches.size();
            }
            
            highlightCurrentMatch();
            updateSearchStatus((currentSearchIndex + 1) + " of " + searchMatches.size());
        }
        
        private void highlightCurrentMatch() {
            if (currentSearchIndex >= 0 && currentSearchIndex < searchMatches.size()) {
                int matchStart = searchMatches.get(currentSearchIndex);
                int matchEnd = matchStart + searchField.getText().length();
                
                jsonDataArea.setSelectionStart(matchStart);
                jsonDataArea.setSelectionEnd(matchEnd);
                jsonDataArea.requestFocus();
            }
        }
        
        private void updateSearchStatus(String message) {
            searchStatusLabel.setText(message);
        }
        
        private void applyFilter() {
            String filterText = filterField.getText().trim();
            
            if (filterText.isEmpty() && !hideEmptyCheckBox.isSelected()) {
                // No filter applied, show all
                objectList.setModel(originalObjectModel);
                return;
            }
            
            // Create filtered model
            filteredObjectModel.clear();
            
            for (int i = 0; i < originalObjectModel.getSize(); i++) {
                String objectName = originalObjectModel.getElementAt(i);
                boolean includeItem = true;
                
                // Apply text filter - search in both object name AND JSON content
                if (!filterText.isEmpty()) {
                    if (filterRegexCheckBox.isSelected()) {
                        try {
                            java.util.regex.Pattern pattern = SafeRegex.safeCompile(filterText,
                                java.util.regex.Pattern.CASE_INSENSITIVE);

                            // Check object name first
                            boolean matchesName = SafeRegex.safeMatches(pattern, objectName);

                            // Check JSON content if name doesn't match
                            boolean matchesContent = false;
                            if (!matchesName) {
                                String jsonData = objectByNameResult.getObjectData(objectName);
                                if (jsonData != null && !jsonData.trim().isEmpty()) {
                                    matchesContent = SafeRegex.safeMatches(pattern, jsonData);
                                }
                            }

                            includeItem = matchesName || matchesContent;
                        } catch (Exception e) {
                            // If regex fails, fall back to plain text matching
                            String lowerFilterText = filterText.toLowerCase();
                            boolean matchesName = objectName.toLowerCase().contains(lowerFilterText);

                            // Check JSON content if name doesn't match
                            boolean matchesContent = false;
                            if (!matchesName) {
                                String jsonData = objectByNameResult.getObjectData(objectName);
                                if (jsonData != null && !jsonData.trim().isEmpty()) {
                                    matchesContent = jsonData.toLowerCase().contains(lowerFilterText);
                                }
                            }

                            includeItem = matchesName || matchesContent;
                        }
                    } else {
                        // Plain text search - search in both object name AND JSON content
                        String lowerFilterText = filterText.toLowerCase();
                        boolean matchesName = objectName.toLowerCase().contains(lowerFilterText);

                        // Check JSON content if name doesn't match
                        boolean matchesContent = false;
                        if (!matchesName) {
                            String jsonData = objectByNameResult.getObjectData(objectName);
                            if (jsonData != null && !jsonData.trim().isEmpty()) {
                                matchesContent = jsonData.toLowerCase().contains(lowerFilterText);
                            }
                        }

                        includeItem = matchesName || matchesContent;
                    }
                }
                
                // Apply hide empty filter
                if (includeItem && hideEmptyCheckBox.isSelected()) {
                    String jsonData = objectByNameResult.getObjectData(objectName);
                    includeItem = !isObjectDataEmpty(jsonData);
                }
                
                if (includeItem) {
                    filteredObjectModel.addElement(objectName);
                }
            }
            
            objectList.setModel(filteredObjectModel);
            
            // Update JSON data area if no selection
            if (objectList.getSelectedIndex() == -1 && filteredObjectModel.getSize() > 0) {
                objectList.setSelectedIndex(0);
            }
        }
        
        private void clearSearch() {
            currentSearchIndex = -1;
            searchMatches.clear();
            lastSearchText = "";
            searchStatusLabel.setText(" ");
            jsonDataArea.setSelectionStart(0);
            jsonDataArea.setSelectionEnd(0);
        }
        
        private void resetAllFilters() {
            searchField.setText("");
            filterField.setText("");
            hideEmptyCheckBox.setSelected(false);
            clearSearch();
            // Reset object list to original
            objectList.setModel(originalObjectModel);
            // Select first item if available
            if (originalObjectModel.getSize() > 0) {
                objectList.setSelectedIndex(0);
            }
        }
        
        /**
         * Check if object data should be considered "empty" for filtering purposes
         */
        private boolean isObjectDataEmpty(String jsonData) {
            if (jsonData == null || jsonData.trim().isEmpty()) {
                return true;
            }
            
            // Check for explicit "No data available" message
            if (jsonData.equals("No data available")) {
                return true;
            }
            
            // Check for "No data found for object" pattern
            if (jsonData.contains("No data found for object") && jsonData.contains("Result: []")) {
                return true;
            }
            
            // Check for empty JSON results (just whitespace and minimal structure)
            String trimmed = jsonData.trim();
            if (trimmed.equals("[]") || trimmed.equals("{}")) {
                return true;
            }
            
            return false;
        }
    }
}