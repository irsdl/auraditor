/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import auraditor.suite.BaseRequest;
import auraditor.core.ThreadManager;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.swing.SwingUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import java.awt.*;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
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
                ThreadManager.createManagedFuture(() -> {
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
                ThreadManager.createManagedFuture(() -> {
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

        public void removeObject(String objectName) {
            objectEntries.remove(objectName);
        }
    }

    /**
     * Data structure for route discovery results
     */
    /**
     * Data class for storing Apex descriptor information
     */
    public static class DescriptorInfo {
        private final String descriptor;
        private final java.util.List<ParameterInfo> parameters;
        private final String sourceUrl;

        public DescriptorInfo(String descriptor, java.util.List<ParameterInfo> parameters, String sourceUrl) {
            this.descriptor = descriptor;
            this.parameters = new java.util.ArrayList<>(parameters);
            this.sourceUrl = sourceUrl;
        }

        public String getDescriptor() {
            return descriptor;
        }

        public java.util.List<ParameterInfo> getParameters() {
            return parameters;
        }

        public String getSourceUrl() {
            return sourceUrl;
        }

        public static class ParameterInfo {
            private final String name;
            private final String type;

            public ParameterInfo(String name, String type) {
                this.name = name;
                this.type = type;
            }

            public String getName() {
                return name;
            }

            public String getType() {
                return type;
            }
        }
    }

    public static class RouteDiscoveryResult {
        private final java.util.Map<String, java.util.List<String>> routeEntries;
        private final String timestamp;

        public RouteDiscoveryResult() {
            this.routeEntries = new java.util.LinkedHashMap<>();
            this.timestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }

        public java.util.Map<String, java.util.List<String>> getRouteEntries() {
            return routeEntries;
        }

        public java.util.Set<String> getCategoryNames() {
            return routeEntries.keySet();
        }

        public java.util.List<String> getRoutesForCategory(String category) {
            return routeEntries.get(category);
        }

        public String getTimestamp() {
            return timestamp;
        }

        public int getTotalCount() {
            return routeEntries.values().stream().mapToInt(List::size).sum();
        }

        public void addRouteCategory(String categoryName, java.util.List<String> routes) {
            routeEntries.put(categoryName, new java.util.ArrayList<>(routes));
        }

        public void removeCategory(String categoryName) {
            routeEntries.remove(categoryName);
        }
    }

    /**
     * Callback interface for result tab creation
     */
    public interface ResultTabCallback {
        void createResultTab(String resultId, String content);
        void createDiscoveryResultTab(String resultId, DiscoveryResult discoveryResult);
        void createObjectByNameTab(String resultId, ObjectByNameResult objectByNameResult);
        void createRecordTab(String resultId, String recordId, String recordData, BaseRequest baseRequest);
        void createDiscoveredRoutesTab(String resultId, RouteDiscoveryResult routeDiscoveryResult);

        // New method for updating route discovery tabs without automatic switching
        default void updateDiscoveredRoutesTab(String resultId, RouteDiscoveryResult routeDiscoveryResult) {
            // Default implementation falls back to createDiscoveredRoutesTab
            createDiscoveredRoutesTab(resultId, routeDiscoveryResult);
        }

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
    private final JCheckBox alwaysCreateNewTabCheckbox;
    private final JButton getRecordByIdBtn;
    private final JTextField recordIdField;
    private final JButton getNavItemsBtn;
    private final JButton getRouterInitializerPathsBtn;
    private final JButton getPotentialPathsFromJSBtn;
    private final JButton findDescriptorsFromSitemapBtn;
    private final JButton performAllSitemapSearchesBtn;
    private final JCheckBox searchSitemapOnlyCheckbox;
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
    private int retrievedRecordsResultCounter = 0;
    private int routeDiscoveryResultCounter = 0;
    private final List<String> availableDiscoveryResults = new ArrayList<>();
    
    // Progress tracking fields for bulk retrieval
    private int totalObjectsToRetrieve = 0;
    private int objectsRetrieved = 0;
    private String currentBulkRetrievalTabId = null;
    private JLabel progressLabel;
    private Thread currentOperationThread = null;

    // Router initializer paths parsing fields
    private volatile boolean routerPathsCancelled = false;
    private volatile boolean jsPathsCancelled = false;
    private volatile boolean descriptorsCancelled = false;
    private volatile boolean operationCancelled = false;
    private Set<String> discoveredRouterPaths = ConcurrentHashMap.newKeySet();
    private Set<String> discoveredJSPaths = ConcurrentHashMap.newKeySet();
    private Set<String> discoveredDescriptors = ConcurrentHashMap.newKeySet();
    private RouteDiscoveryResult currentRouterPathsResults = null;
    private RouteDiscoveryResult currentJSPathsResults = null;
    private RouteDiscoveryResult currentDescriptorResults = null;

    // Compiled regex patterns for router initializer extraction
    private static final Pattern ROUTER_INITIALIZER_PATTERN = Pattern.compile(
        "\"componentDef\":\\s*\\{[^}]*\"descriptor\":\\s*\"[^\"]*routerInitializer\"",
        Pattern.CASE_INSENSITIVE
    );

    // Compiled regex patterns for JavaScript path extraction
    private static final Pattern JS_RELATIVE_PATH_PATTERN = Pattern.compile(
        "(?:[\"'`])((?:\\.{0,2}/|/)[^\"'`\\s<>{}\\[\\]\\\\]+(?:/[^\"'`\\s<>{}\\[\\]\\\\]*)*(?:\\.[a-zA-Z0-9]{1,10})?)(?:[\"'`])",
        Pattern.MULTILINE
    );

    /**
     * Validate if a path should be included in results
     * Filters out comment blocks and image/font file extensions
     */
    private boolean isValidPath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return false;
        }

        // Remove paths that are comments (start with /* and end with */)
        if (path.startsWith("/*") && path.endsWith("*/")) {
            return false;
        }

        // Get the path without query string for extension checking
        String pathWithoutQuery = path.split("\\?")[0];

        // Remove paths ending with image or font file extensions
        String[] unwantedExtensions = {
            ".svg", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".otf"
        };

        for (String extension : unwantedExtensions) {
            if (pathWithoutQuery.toLowerCase().endsWith(extension)) {
                return false;
            }
        }

        return true;
    }

    private static final Pattern JS_URL_PATH_PATTERN = Pattern.compile(
        "(?:[\"'`])(https?://[^/\"'`\\s<>{}\\[\\]\\\\]+(/[^\"'`\\s<>{}\\[\\]\\\\]*(?:/[^\"'`\\s<>{}\\[\\]\\\\]*)*)?)(?:[\"'`])",
        Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    private static final Pattern JS_PARAMETERIZED_PATH_PATTERN = Pattern.compile(
        "(?:[\"'`])((?:\\.{0,2}/|/)[^\"'`\\s<>{}\\[\\]\\\\]*\\{[^}]+\\}[^\"'`\\s<>{}\\[\\]\\\\]*(?:/[^\"'`\\s<>{}\\[\\]\\\\]*)*)(?:[\"'`])",
        Pattern.MULTILINE
    );

    // Pattern to exclude regex patterns and other non-path strings
    private static final Pattern JS_EXCLUDE_PATTERN = Pattern.compile(
        ".*(?:\\\\[dDwWsSbBrntfv]|\\[\\^?[^\\]]*\\]|\\{\\d+(?:,\\d*)?\\}|\\(\\?[:=!<]|\\\\[uUx][0-9a-fA-F]|function\\s*\\(|var\\s+|let\\s+|const\\s+|return\\s+).*",
        Pattern.CASE_INSENSITIVE
    );

    // Compiled regex patterns for Apex descriptor extraction
    private static final Pattern APEX_DESCRIPTOR_PATTERN = Pattern.compile(
        "apex://[\\w\\._\\-$]+/ACTION\\$[\\w\\._\\-$]+",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DESCRIPTOR_CONTEXT_PATTERN = Pattern.compile(
        "\"descriptor\"\\s*:\\s*\"(apex://[\\w\\._\\-$]+/ACTION\\$[\\w\\._\\-$]+)\"[^}]*?\"pa\"\\s*:\\s*(\\[[^\\]]*\\])",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // Alternative pattern for descriptors without parameter context
    private static final Pattern DESCRIPTOR_SIMPLE_PATTERN = Pattern.compile(
        "\"descriptor\"\\s*:\\s*\"(apex://[\\w\\._\\-$]+/ACTION\\$[\\w\\._\\-$]+)\"",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PARAMETER_PATTERN = Pattern.compile(
        "\\{\\s*\"name\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"type\"\\s*:\\s*\"([^\"]+)\"\\s*\\}",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ROUTES_PATTERN = Pattern.compile(
        "\"routes\":\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern ROUTE_PATH_PATTERN = Pattern.compile(
        "\"(/[^\"]+)\":\\s*\\{",
        Pattern.CASE_INSENSITIVE
    );
    // Enhanced pattern for finding routes object with better nested handling
    private static final Pattern ROUTES_OBJECT_PATTERN = Pattern.compile(
        "\"routes\":\\s*\\{",
        Pattern.CASE_INSENSITIVE
    );
    
    // Object storage for discovered objects
    private final Set<String> discoveredDefaultObjects = new HashSet<>();
    private final Set<String> discoveredCustomObjects = new HashSet<>();
    
    // Object by name results storage
    private ObjectByNameResult objectByNameResults = new ObjectByNameResult();
    private final Map<String, ObjectByNameResult> tabObjectResults = new HashMap<>();
    
    // Object discovery payload
    private static final String DISCOVERY_PAYLOAD = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{}}]}";
    private static final String ROUTE_DISCOVERY_PAYLOAD = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"aura://AppsController/ACTION$getNavItems\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"inContextOfComponent\":\"\",\"mode\":\"VIEW\",\"layoutType\":\"FULL\",\"defaultFieldValues\":null,\"navigationLocation\":\"LIST_VIEW_ROW\"}}]}";
    
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
        this.threadCountSpinner = new JSpinner(new SpinnerNumberModel(1, 1, Integer.MAX_VALUE, 1));
        this.findDefaultObjectsPresetBtn = new JButton("Scan with Wordlist");
        this.selectWordlistBtn = new JButton("Choose File...");
        this.usePresetWordlistCheckbox = new JCheckBox("Use built-in wordlist", true);
        this.alwaysCreateNewTabCheckbox = new JCheckBox("Always create new tab", false);
        this.getRecordByIdBtn = new JButton("Get Record by ID");
        this.recordIdField = new JTextField(15);
        this.getNavItemsBtn = new JButton("Get Nav Items");
        this.getRouterInitializerPathsBtn = new JButton("Router Initializer Paths From Sitemap");
        this.getPotentialPathsFromJSBtn = new JButton("Potential Paths From Sitemap");
        this.findDescriptorsFromSitemapBtn = new JButton("Find Descriptors From Sitemap");
        this.performAllSitemapSearchesBtn = new JButton("Perform All Sitemap Searches");
        this.searchSitemapOnlyCheckbox = new JCheckBox("Search sitemap only", true);
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

        // Get Record by ID section
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JLabel recordLabel = new JLabel("Get Record by ID");
        recordLabel.setFont(recordLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(recordLabel, gbc);

        gbc.gridy++; gbc.gridwidth = 1; gbc.gridx = 0;
        getRecordByIdBtn.setText("Get Record by ID");
        getRecordByIdBtn.setToolTipText("Get a specific record by its ID (sends 1 request)");
        getRecordByIdBtn.setEnabled(false); // Initially disabled until text is entered
        actionsPanel.add(getRecordByIdBtn, gbc);

        gbc.gridx = 1;
        recordIdField.setPreferredSize(new Dimension(200, 25));
        recordIdField.setToolTipText("Enter the record ID to retrieve");
        actionsPanel.add(recordIdField, gbc);

        // Active Router Discovery section
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JLabel activeRouteLabel = new JLabel("Active Router Discovery");
        activeRouteLabel.setFont(activeRouteLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(activeRouteLabel, gbc);

        // Active route discovery (sends HTTP request)
        gbc.gridy++; gbc.gridwidth = 2; gbc.gridx = 0;
        getNavItemsBtn.setText("Get Nav Items");
        getNavItemsBtn.setToolTipText("Discover navigation items and routes by sending HTTP request");
        getNavItemsBtn.setEnabled(false); // Initially disabled until baseline request is selected
        actionsPanel.add(getNavItemsBtn, gbc);

        // Passive Router Discovery section
        gbc.gridx = 0; gbc.gridy++; gbc.gridwidth = 2;
        JLabel passiveRouteLabel = new JLabel("Passive Router Discovery");
        passiveRouteLabel.setFont(passiveRouteLabel.getFont().deriveFont(Font.BOLD, 14f));
        actionsPanel.add(passiveRouteLabel, gbc);

        // Passive sitemap parsing (no HTTP requests)
        gbc.gridy++; gbc.gridwidth = 1; gbc.gridx = 0;
        getRouterInitializerPathsBtn.setToolTipText("Extract router initializer paths from existing sitemap data (passive)");
        getRouterInitializerPathsBtn.setEnabled(true); // Passive buttons enabled by default (no baseline request needed)
        actionsPanel.add(getRouterInitializerPathsBtn, gbc);

        gbc.gridx = 1;
        getPotentialPathsFromJSBtn.setToolTipText("Extract potential paths from JavaScript files in sitemap (passive)");
        getPotentialPathsFromJSBtn.setEnabled(true); // Passive buttons enabled by default (no baseline request needed)
        actionsPanel.add(getPotentialPathsFromJSBtn, gbc);

        gbc.gridy++; gbc.gridwidth = 1; gbc.gridx = 0;
        findDescriptorsFromSitemapBtn.setToolTipText("Extract Apex descriptors from JavaScript files in sitemap (passive)");
        findDescriptorsFromSitemapBtn.setEnabled(true); // Passive buttons enabled by default (no baseline request needed)
        actionsPanel.add(findDescriptorsFromSitemapBtn, gbc);

        gbc.gridy++; gbc.gridwidth = 2; gbc.gridx = 0;
        performAllSitemapSearchesBtn.setToolTipText("Perform all three sitemap searches at once (router paths, JS paths, and descriptors)");
        performAllSitemapSearchesBtn.setEnabled(true); // Passive buttons enabled by default (no baseline request needed)
        actionsPanel.add(performAllSitemapSearchesBtn, gbc);

        gbc.gridy++; gbc.gridwidth = 2; gbc.gridx = 0;
        searchSitemapOnlyCheckbox.setToolTipText("When checked, limit passive parsing to sitemap only (applies to sitemap parsing buttons above)");
        actionsPanel.add(searchSitemapOnlyCheckbox, gbc);

        // Thread count configuration
        gbc.gridy++; gbc.gridwidth = 2; gbc.weighty = 0.0;
        JPanel threadPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        threadPanel.add(new JLabel("Concurrent requests:"));
        threadCountSpinner.setPreferredSize(new Dimension(60, 25));
        threadCountSpinner.setToolTipText("Number of concurrent requests for bulk operations (1-10)");
        threadPanel.add(threadCountSpinner);
        threadPanel.add(new JLabel("(reduces server load with lower values)"));
        actionsPanel.add(threadPanel, gbc);

        // Tab preference configuration
        gbc.gridy++; gbc.gridwidth = 2; gbc.weighty = 0.0;
        JPanel tabPreferencePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        alwaysCreateNewTabCheckbox.setToolTipText("Skip tab choice dialog and always create new tabs for object results");
        tabPreferencePanel.add(alwaysCreateNewTabCheckbox);
        actionsPanel.add(tabPreferencePanel, gbc);

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
            Timer timer = ThreadManager.createManagedTimer(5000, e -> clearStatusMessage());
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

        // Disable all action buttons
        findAllObjectNamesBtn.setEnabled(false);
        findDefaultObjectsBtn.setEnabled(false);
        findCustomObjectsBtn.setEnabled(false);
        findAllObjectsBtn.setEnabled(false);
        findObjectByNameBtn.setEnabled(false);
        findDefaultObjectsPresetBtn.setEnabled(false);
        getRecordByIdBtn.setEnabled(false);
        getNavItemsBtn.setEnabled(false);
        getRouterInitializerPathsBtn.setEnabled(false);
        getPotentialPathsFromJSBtn.setEnabled(false);
        findDescriptorsFromSitemapBtn.setEnabled(false);

        // Disable all input controls
        requestSelector.setEnabled(false);
        objectNameField.setEnabled(false);
        recordIdField.setEnabled(false);
        threadCountSpinner.setEnabled(false);
        discoveryResultSelector.setEnabled(false);
        usePresetWordlistCheckbox.setEnabled(false);
        selectWordlistBtn.setEnabled(false);
        alwaysCreateNewTabCheckbox.setEnabled(false);

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

        // Explicitly restore passive search button texts in case they were updated with progress
        // This ensures buttons show their original labels even if progress updates bypassed setBusyState
        getRouterInitializerPathsBtn.setText("Router Initializer Paths From Sitemap");
        getPotentialPathsFromJSBtn.setText("Potential Paths From Sitemap");
        findDescriptorsFromSitemapBtn.setText("Find Descriptors From Sitemap");
        performAllSitemapSearchesBtn.setText("Perform All Sitemap Searches");

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
     * Generate result ID for route discovery operations
     */
    private String generateRouteDiscoveryResultId() {
        routeDiscoveryResultCounter++;
        return "Discovered Routes " + routeDiscoveryResultCounter;
    }

    /**
     * Generate result ID for route discovery operations with tab reuse check
     */
    private String generateRouteDiscoveryResultIdWithReuseCheck() {
        // If user prefers to always create new tabs, always create new
        if (alwaysCreateNewTabCheckbox.isSelected()) {
            routeDiscoveryResultCounter++;
            return "Discovered Routes " + routeDiscoveryResultCounter;
        }

        // Check if we have existing route discovery tabs to reuse
        boolean hasExistingTabs = routeDiscoveryResultCounter > 0;

        if (!hasExistingTabs) {
            // No existing tabs, create first one
            routeDiscoveryResultCounter++;
            return "Discovered Routes " + routeDiscoveryResultCounter;
        } else {
            // Reuse the most recent tab
            return "Discovered Routes " + routeDiscoveryResultCounter;
        }
    }

    /**
     * Check if existing tabs should be reused instead of creating new ones
     */
    private boolean shouldReuseTab() {
        return !alwaysCreateNewTabCheckbox.isSelected() && routeDiscoveryResultCounter > 0;
    }

    /**
     * Generate timestamp string for category names
     */
    private String generateTimestamp() {
        return java.time.LocalDateTime.now().format(
            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        );
    }

    /**
     * Generate result ID for object by name operations
     */
    private String generateObjByNameResultId(int requestId) {
        objByNameResultCounter++;
        return "ObjByName-Request" + requestId + "-" + objByNameResultCounter;
    }

    /**
     * Generate result ID for retrieved records operations
     */
    private String generateRetrievedRecordsResultId() {
        retrievedRecordsResultCounter++;
        return "Retrieved Records " + retrievedRecordsResultCounter;
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
        boolean hasExistingTabs = retrievedObjectsResultCounter > 0;

        // If user prefers to always create new tabs, always create new
        if (alwaysCreateNewTabCheckbox.isSelected()) {
            objectByNameResults = new ObjectByNameResult();
            return generateRetrievedObjectsResultId();
        }

        // If checkbox is unchecked, prefer appending to existing tabs
        if (hasExistingTabs) {
            // Append to existing tab automatically
            String lastTabId = "Retrieved Objects " + retrievedObjectsResultCounter;
            return lastTabId;
        } else {
            // No existing tabs, create new tab
            objectByNameResults = new ObjectByNameResult();
            return generateRetrievedObjectsResultId();
        }
    }
    
    /**
     * Get user's choice for tab handling when performing bulk retrieval
     */
    private String getUserTabChoiceForBulkRetrieval(String objectType, int objectCount) {
        // Check if there are existing retrieved objects tabs
        boolean hasExistingTabs = retrievedObjectsResultCounter > 0;

        // If user prefers to always create new tabs, always create new
        if (alwaysCreateNewTabCheckbox.isSelected()) {
            objectByNameResults = new ObjectByNameResult();
            return generateRetrievedObjectsResultId();
        }

        // If checkbox is unchecked, prefer appending to existing tabs
        if (hasExistingTabs) {
            // Append to existing tab automatically
            String lastTabId = "Retrieved Objects " + retrievedObjectsResultCounter;
            // Load existing results from the tab to preserve contents
            ObjectByNameResult existingResults = tabObjectResults.get(lastTabId);
            if (existingResults != null) {
                objectByNameResults = existingResults; // Use existing results for appending
            }
            return lastTabId;
        } else {
            // No existing tabs, create new tab
            objectByNameResults = new ObjectByNameResult();
            return generateRetrievedObjectsResultId();
        }
    }

    /**
     * Get user's choice for tab handling when retrieving records
     */
    private String getUserTabChoiceForRecordRetrieval(String recordId) {
        // Check if there are existing retrieved records tabs
        boolean hasExistingTabs = retrievedRecordsResultCounter > 0;

        // If user prefers to always create new tabs, always create new
        if (alwaysCreateNewTabCheckbox.isSelected()) {
            return generateRetrievedRecordsResultId();
        }

        // If checkbox is unchecked, prefer appending to existing tabs
        if (hasExistingTabs) {
            // Append to existing tab automatically
            String lastTabId = "Retrieved Records " + retrievedRecordsResultCounter;
            return lastTabId;
        } else {
            // No existing tabs, create new tab
            return generateRetrievedRecordsResultId();
        }
    }

    /**
     * Add a discovery result to the available results list
     */
    private void addDiscoveryResult(String resultId) {
        availableDiscoveryResults.add(resultId);
        discoveryResultSelector.addItem(resultId);

        // Only enable discovery result selector if not currently processing
        if (!isProcessing) {
            discoveryResultSelector.setEnabled(true);
        }
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
            
            // Send the request with preserved HTTP version
            api.logging().logToOutput("Sending discovery request to: " + originalRequest.url());
            HttpRequestResponse response = sendRequestWithPreservedHttpVersion(discoveryRequest, baseRequest);
            
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
     * Perform route discovery by sending the route discovery payload and parsing the response
     */
    private void performRouteDiscovery(BaseRequest baseRequest, String resultId) {
        api.logging().logToOutput("Starting route discovery with baseline request...");

        try {
            // Create a modified request with the route discovery payload in the message parameter
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();
            HttpRequest routeDiscoveryRequest = modifyMessageParameter(originalRequest, ROUTE_DISCOVERY_PAYLOAD);

            // Send the request with preserved HTTP version
            api.logging().logToOutput("Sending route discovery request to: " + originalRequest.url());
            HttpRequestResponse response = sendRequestWithPreservedHttpVersion(routeDiscoveryRequest, baseRequest);

            if (response.response() == null) {
                throw new RuntimeException("No response received");
            }

            // Parse the response to extract navigation items
            String responseBody = response.response().bodyToString();
            api.logging().logToOutput("Route discovery response received, parsing navigation items...");

            parseRouteDiscoveryResponse(responseBody, resultId, baseRequest.getId());

        } catch (Exception e) {
            api.logging().logToError("Route discovery failed: " + e.getMessage());
            throw e;
        }
    }

    /**
     * TODO: Implement passive sitemap parsing for router initializer paths
     * This is a passive operation that parses existing sitemap data without sending HTTP requests
     * Should respect the searchSitemapOnlyCheckbox state
     *
     * NOTE: In the future, this method may be merged with parseSitemapJSPaths() to avoid
     * parsing the sitemap twice for efficiency. Currently kept separate for implementation phase.
     *
     * @param baseRequest Can be null since passive operations don't require baseline HTTP requests
     */
    private void parseSitemapRouterPaths(BaseRequest baseRequest, String resultId, boolean sitemapOnly) {
        api.logging().logToOutput("Starting passive sitemap parsing for router initializer paths (sitemap only: " + sitemapOnly + ")...");

        try {
            // Reset cancellation flag and discovered paths
            routerPathsCancelled = false;
            discoveredRouterPaths.clear();

            // Initialize results
            currentRouterPathsResults = new RouteDiscoveryResult();

            // Generate session timestamp that will be used for the entire parsing session
            String sessionTimestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            // Get sitemap items
            api.logging().logToOutput("Retrieving sitemap entries...");
            List<HttpRequestResponse> sitemapItems = new ArrayList<>();

            // Get all sitemap items (access actual sitemap, not just proxy history)
            sitemapItems.addAll(api.siteMap().requestResponses());

            // Filter for JavaScript content-type and optionally scope
            List<HttpRequestResponse> jsResponses = new ArrayList<>();
            for (HttpRequestResponse item : sitemapItems) {
                if (routerPathsCancelled) {
                    api.logging().logToOutput("Router paths parsing cancelled by user");
                    return;
                }

                try {
                    if (item.response() != null &&
                        item.response().mimeType() == MimeType.SCRIPT) {

                        // Apply scope filtering if enabled
                        if (!sitemapOnly || api.scope().isInScope(item.request().url())) {
                            jsResponses.add(item);
                        }
                    }
                } catch (Exception e) {
                    // Skip malformed items
                    api.logging().logToOutput("Skipping malformed sitemap item: " + e.getMessage());
                    continue;
                }
            }

            api.logging().logToOutput("Found " + jsResponses.size() + " JavaScript responses to analyze");

            // Progress tracking
            AtomicInteger processedItems = new AtomicInteger(0);
            int totalItems = jsResponses.size();

            if (totalItems == 0) {
                SwingUtilities.invokeLater(() -> {
                    clearBusyState();
                    showStatusMessage("No JavaScript responses found in sitemap", Color.ORANGE);
                });
                return;
            }

            // Process each JavaScript response
            for (HttpRequestResponse item : jsResponses) {
                if (routerPathsCancelled) {
                    api.logging().logToOutput("Router paths parsing cancelled by user");
                    SwingUtilities.invokeLater(() -> {
                        clearBusyState();
                        showStatusMessage("Router paths parsing cancelled", Color.ORANGE);
                    });
                    return;
                }

                try {
                    // Process the JavaScript response
                    processJavaScriptResponseForRouterPaths(item, resultId, sessionTimestamp);

                    // Update progress
                    int processed = processedItems.incrementAndGet();
                    int progress = (processed * 100) / totalItems;

                    SwingUtilities.invokeLater(() -> {
                        // Update button text with progress
                        getRouterInitializerPathsBtn.setText("⟳ Router Paths (" + progress + "%)");
                    });

                } catch (Exception e) {
                    api.logging().logToOutput("Error processing JavaScript response: " + e.getMessage());
                    processedItems.incrementAndGet(); // Still count as processed
                    continue;
                }
            }

            // Finalize results
            SwingUtilities.invokeLater(() -> {
                finalizeRouterPathsResults(resultId, sessionTimestamp);

                clearBusyState();
                int pathsFound = discoveredRouterPaths.size();
                showStatusMessage("✓ Router paths parsing completed: " + pathsFound + " unique paths found",
                                pathsFound > 0 ? Color.GREEN : Color.ORANGE);

                api.logging().logToOutput("Router paths parsing completed successfully:");
                api.logging().logToOutput("  JavaScript responses analyzed: " + totalItems);
                api.logging().logToOutput("  Unique router paths found: " + pathsFound);
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Failed to parse router paths from sitemap: " + e.getMessage());
            });
            throw new RuntimeException("Failed to parse router paths from sitemap", e);
        }
    }

    /**
     * Process a JavaScript response to extract router initializer paths
     */
    private void processJavaScriptResponseForRouterPaths(HttpRequestResponse item, String resultId, String sessionTimestamp) {
        try {
            String responseBody = item.response().bodyToString();

            // First check if this response contains routerInitializer
            Matcher routerMatcher = ROUTER_INITIALIZER_PATTERN.matcher(responseBody);
            if (!routerMatcher.find()) {
                return; // No routerInitializer found in this response
            }

            // Enhanced approach: Find routes object and extract using balanced brace matching
            extractRoutesFromJson(responseBody, resultId, sessionTimestamp);

        } catch (Exception e) {
            api.logging().logToOutput("Error extracting router paths from JavaScript response: " + e.getMessage());
        }
    }

    /**
     * Enhanced route extraction using balanced brace matching for complex nested JSON
     */
    private void extractRoutesFromJson(String responseBody, String resultId, String sessionTimestamp) {
        try {
            // Find the start of the routes object
            Matcher routesObjectMatcher = ROUTES_OBJECT_PATTERN.matcher(responseBody);

            while (routesObjectMatcher.find()) {
                int routesStart = routesObjectMatcher.end() - 1; // Position of opening brace

                // Find the matching closing brace using balanced counting
                String routesJson = extractBalancedBraces(responseBody, routesStart);

                if (routesJson != null && !routesJson.isEmpty()) {
                    // Try to parse as JSON for robust extraction
                    extractRoutePathsFromRoutesJson(routesJson, resultId, sessionTimestamp);

                    // Fallback: Also try regex pattern matching for additional coverage
                    extractRoutePathsWithRegex(routesJson, resultId, sessionTimestamp);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error in enhanced route extraction: " + e.getMessage());
        }
    }

    /**
     * Extract balanced braces content starting from a given position
     */
    private String extractBalancedBraces(String text, int startPos) {
        if (startPos >= text.length() || text.charAt(startPos) != '{') {
            return null;
        }

        int braceCount = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = startPos; i < text.length(); i++) {
            char c = text.charAt(i);

            if (escaped) {
                escaped = false;
                continue;
            }

            if (c == '\\' && inString) {
                escaped = true;
                continue;
            }

            if (c == '"') {
                inString = !inString;
                continue;
            }

            if (!inString) {
                if (c == '{') {
                    braceCount++;
                } else if (c == '}') {
                    braceCount--;
                    if (braceCount == 0) {
                        return text.substring(startPos, i + 1);
                    }
                }
            }
        }

        return null; // Unbalanced braces
    }

    /**
     * Extract route paths using JSON parsing approach
     */
    private void extractRoutePathsFromRoutesJson(String routesJson, String resultId, String sessionTimestamp) {
        try {
            // Use Jackson to parse the routes JSON
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode routesNode = mapper.readTree(routesJson);

            // Iterate through all field names (which are the route paths)
            routesNode.fieldNames().forEachRemaining(routePath -> {
                if (routePath.startsWith("/") && isValidPath(routePath)) {
                    // Add to discovered paths (Set automatically handles duplicates)
                    if (discoveredRouterPaths.add(routePath)) {
                        // New path discovered - just log it, will be added in batch at the end
                        api.logging().logToOutput("Found router path (JSON): " + routePath);
                    }
                }
            });

        } catch (Exception e) {
            // JSON parsing failed, not necessarily an error as fallback will handle it
            api.logging().logToOutput("JSON parsing failed for routes, using regex fallback: " + e.getMessage());
        }
    }

    /**
     * Fallback regex-based route extraction for additional coverage
     */
    private void extractRoutePathsWithRegex(String routesContent, String resultId, String sessionTimestamp) {
        try {
            // Extract individual route paths using improved regex
            Pattern enhancedRoutePattern = Pattern.compile("\"(/[^\"]+?)\"\\s*:", Pattern.CASE_INSENSITIVE);
            Matcher pathMatcher = enhancedRoutePattern.matcher(routesContent);

            while (pathMatcher.find()) {
                String routePath = pathMatcher.group(1);

                // Add to discovered paths (Set automatically handles duplicates) with validation
                if (isValidPath(routePath) && discoveredRouterPaths.add(routePath)) {
                    // New path discovered - just log it, will be added in batch at the end
                    api.logging().logToOutput("Found router path (regex): " + routePath);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error in regex route extraction: " + e.getMessage());
        }
    }

    /**
     * Finalize router paths results by adding all discovered paths in batch
     */
    private void finalizeRouterPathsResults(String resultId, String sessionTimestamp) {
        if (currentRouterPathsResults != null && !discoveredRouterPaths.isEmpty()) {
            String categoryName = "Router Initializer Paths (" + sessionTimestamp + ")";

            // Convert Set to List for the results
            List<String> pathsList = new ArrayList<>(discoveredRouterPaths);

            // Clear any existing category with the same name (in case of tab reuse)
            if (shouldReuseTab()) {
                // Remove old category to replace with new results
                currentRouterPathsResults.getRouteEntries().remove(categoryName);
            }

            // Add all paths to results in one batch
            currentRouterPathsResults.addRouteCategory(categoryName, pathsList);

            // Update the results tab
            if (resultTabCallback != null) {
                if (shouldReuseTab()) {
                    resultTabCallback.updateDiscoveredRoutesTab(resultId, currentRouterPathsResults);
                } else {
                    resultTabCallback.createDiscoveredRoutesTab(resultId, currentRouterPathsResults);
                }
            }

            api.logging().logToOutput("Finalized router paths results: " + pathsList.size() + " paths in category '" + categoryName + "'");
        }
    }

    /**
     * Add a router path to the results tab immediately (deprecated - kept for compatibility)
     */
    private void addRouterPathToResults(String path, String resultId) {
        // This method is now deprecated in favor of batch processing
        // Left for compatibility but no longer used in new code
    }

    /**
     * Cancel router paths parsing operation
     */
    private void cancelRouterPathsParsing() {
        routerPathsCancelled = true;
        api.logging().logToOutput("Router paths parsing cancellation requested");
    }

    private void cancelJSPathsParsing() {
        jsPathsCancelled = true;
        api.logging().logToOutput("JS paths parsing cancellation requested");
    }

    private void cancelDescriptorsParsing() {
        descriptorsCancelled = true;
        api.logging().logToOutput("Descriptors parsing cancellation requested");
    }

    /**
     * TODO: Implement passive sitemap parsing for potential JavaScript paths
     * This is a passive operation that parses existing sitemap data without sending HTTP requests
     * Should respect the searchSitemapOnlyCheckbox state
     *
     * NOTE: In the future, this method may be merged with parseSitemapRouterPaths() to avoid
     * parsing the sitemap twice for efficiency. Currently kept separate for implementation phase.
     *
     * @param baseRequest Can be null since passive operations don't require baseline HTTP requests
     */
    private void parseSitemapJSPaths(BaseRequest baseRequest, String resultId, boolean sitemapOnly) {
        api.logging().logToOutput("Starting passive sitemap parsing for JS paths (sitemap only: " + sitemapOnly + ")...");

        try {
            // Reset cancellation flag and discovered paths
            jsPathsCancelled = false;
            discoveredJSPaths.clear();

            // Initialize results
            currentJSPathsResults = new RouteDiscoveryResult();

            // Generate timestamp for this parsing session
            String sessionTimestamp = generateTimestamp();

            // Get sitemap items
            api.logging().logToOutput("Retrieving sitemap entries...");
            List<HttpRequestResponse> sitemapItems = new ArrayList<>();

            // Get all sitemap items (access actual sitemap, not just proxy history)
            sitemapItems.addAll(api.siteMap().requestResponses());

            api.logging().logToOutput("Total sitemap items retrieved: " + sitemapItems.size());

            // Filter for JavaScript responses
            List<HttpRequestResponse> jsResponses = new ArrayList<>();
            for (HttpRequestResponse item : sitemapItems) {
                // Check for cancellation
                if (jsPathsCancelled || operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("JS paths parsing cancelled by user");
                    return;
                }

                try {
                    if (item.response() != null &&
                        item.response().mimeType() == MimeType.SCRIPT) {

                        // Apply scope filtering if enabled
                        if (!sitemapOnly || api.scope().isInScope(item.request().url())) {
                            jsResponses.add(item);
                        }
                    }
                } catch (Exception e) {
                    // Skip malformed items
                    api.logging().logToOutput("Skipping malformed sitemap item: " + e.getMessage());
                    continue;
                }
            }

            api.logging().logToOutput("Found " + jsResponses.size() + " JavaScript responses to analyze");

            if (jsResponses.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    clearBusyState();
                    showStatusMessage("No JavaScript responses found in sitemap", Color.ORANGE);
                });
                return;
            }

            // Process JavaScript responses to extract paths
            int totalResponses = jsResponses.size();
            int processedResponses = 0;

            for (HttpRequestResponse jsResponse : jsResponses) {
                // Check for cancellation
                if (jsPathsCancelled || operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("JS paths parsing cancelled by user");
                    SwingUtilities.invokeLater(() -> {
                        clearBusyState();
                        if (!discoveredJSPaths.isEmpty()) {
                            showStatusMessage("Operation cancelled - " + discoveredJSPaths.size() + " JS paths found so far", Color.ORANGE);
                            // Create or update tab with whatever data was collected
                            if (resultTabCallback != null && currentJSPathsResults != null) {
                                if (shouldReuseTab()) {
                                    resultTabCallback.updateDiscoveredRoutesTab(resultId, currentJSPathsResults);
                                } else {
                                    resultTabCallback.createDiscoveredRoutesTab(resultId, currentJSPathsResults);
                                }
                            }
                        } else {
                            showStatusMessage("Operation cancelled", Color.RED);
                        }
                    });
                    return;
                }

                processedResponses++;
                final int currentProgress = (processedResponses * 100) / totalResponses;

                SwingUtilities.invokeLater(() -> {
                    getPotentialPathsFromJSBtn.setText("⟳ JS Paths (" + currentProgress + "%)");
                });

                try {
                    processJavaScriptResponseForPaths(jsResponse, baseRequest, sessionTimestamp);
                } catch (Exception e) {
                    api.logging().logToError("Error processing JavaScript response for paths: " + e.getMessage());
                }
            }

            api.logging().logToOutput("Completed JS paths parsing. Found " + discoveredJSPaths.size() + " unique paths");

            // Finalize results
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                if (!discoveredJSPaths.isEmpty()) {
                    showStatusMessage("✓ JS Paths parsing completed - " + discoveredJSPaths.size() + " paths found", Color.GREEN);
                    if (resultTabCallback != null && currentJSPathsResults != null) {
                        if (shouldReuseTab()) {
                            resultTabCallback.updateDiscoveredRoutesTab(resultId, currentJSPathsResults);
                        } else {
                            resultTabCallback.createDiscoveredRoutesTab(resultId, currentJSPathsResults);
                        }
                    }
                } else {
                    showStatusMessage("JS Paths parsing completed - no paths found", Color.ORANGE);
                }
            });

        } catch (Exception e) {
            api.logging().logToError("Exception in parseSitemapJSPaths: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showStatusMessage("Error during JS paths parsing: " + e.getMessage(), Color.RED);
            });
        }
    }

    /**
     * Parse sitemap for Apex descriptors and their parameters
     * This is a passive operation that parses existing sitemap data without sending HTTP requests
     * Should respect the searchSitemapOnlyCheckbox state
     */
    private void parseSitemapDescriptors(BaseRequest baseRequest, String resultId, boolean sitemapOnly) {
        api.logging().logToOutput("Starting passive sitemap parsing for Apex descriptors (sitemap only: " + sitemapOnly + ")...");

        try {
            // Reset cancellation flag and discovered descriptors
            descriptorsCancelled = false;
            discoveredDescriptors.clear();

            // Initialize results
            currentDescriptorResults = new RouteDiscoveryResult();
            final String sessionTimestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

            // Get sitemap items
            api.logging().logToOutput("Retrieving sitemap entries...");
            List<HttpRequestResponse> sitemapItems = new ArrayList<>();

            // Get all sitemap items (access actual sitemap, not just proxy history)
            sitemapItems.addAll(api.siteMap().requestResponses());

            api.logging().logToOutput("Total sitemap items retrieved: " + sitemapItems.size());

            // Filter for JavaScript responses
            List<HttpRequestResponse> jsResponses = new ArrayList<>();
            for (HttpRequestResponse item : sitemapItems) {
                // Check for cancellation
                if (descriptorsCancelled || operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Descriptors parsing cancelled by user");
                    return;
                }

                try {
                    if (item.response() != null &&
                        item.response().mimeType() == MimeType.SCRIPT) {

                        // Apply scope filtering if enabled
                        if (!sitemapOnly || api.scope().isInScope(item.request().url())) {
                            jsResponses.add(item);
                        }
                    }
                } catch (Exception e) {
                    // Skip malformed items
                    api.logging().logToOutput("Skipping malformed sitemap item: " + e.getMessage());
                    continue;
                }
            }

            api.logging().logToOutput("Found " + jsResponses.size() + " JavaScript responses to analyze");

            if (jsResponses.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    clearBusyState();
                    showStatusMessage("No JavaScript responses found in sitemap", Color.ORANGE);
                });
                return;
            }

            // Process JavaScript responses to extract descriptors
            int totalResponses = jsResponses.size();
            int processedResponses = 0;

            for (HttpRequestResponse jsResponse : jsResponses) {
                // Check for cancellation
                if (descriptorsCancelled || operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Descriptors parsing cancelled by user");
                    SwingUtilities.invokeLater(() -> {
                        clearBusyState();
                        if (!discoveredDescriptors.isEmpty()) {
                            showStatusMessage("Operation cancelled - " + discoveredDescriptors.size() + " descriptors found so far", Color.ORANGE);
                            // Create or update tab with whatever data was collected
                            if (resultTabCallback != null && currentDescriptorResults != null) {
                                if (shouldReuseTab()) {
                                    resultTabCallback.updateDiscoveredRoutesTab(resultId, currentDescriptorResults);
                                } else {
                                    resultTabCallback.createDiscoveredRoutesTab(resultId, currentDescriptorResults);
                                }
                            }
                        } else {
                            showStatusMessage("Operation cancelled", Color.RED);
                        }
                    });
                    return;
                }

                processedResponses++;
                final int currentProgress = (processedResponses * 100) / totalResponses;

                SwingUtilities.invokeLater(() -> {
                    findDescriptorsFromSitemapBtn.setText("⟳ Descriptors (" + currentProgress + "%)");
                });

                try {
                    processJavaScriptResponseForDescriptors(jsResponse, sessionTimestamp);
                } catch (Exception e) {
                    api.logging().logToError("Error processing JavaScript response for descriptors: " + e.getMessage());
                }
            }

            api.logging().logToOutput("Completed descriptors parsing. Found " + discoveredDescriptors.size() + " unique descriptors");

            // Finalize results
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                if (!discoveredDescriptors.isEmpty()) {
                    showStatusMessage("✓ Descriptors parsing completed - " + discoveredDescriptors.size() + " descriptors found", Color.GREEN);
                    if (resultTabCallback != null && currentDescriptorResults != null) {
                        if (shouldReuseTab()) {
                            resultTabCallback.updateDiscoveredRoutesTab(resultId, currentDescriptorResults);
                        } else {
                            resultTabCallback.createDiscoveredRoutesTab(resultId, currentDescriptorResults);
                        }
                    }
                } else {
                    showStatusMessage("Descriptors parsing completed - no descriptors found", Color.ORANGE);
                }
            });

        } catch (Exception e) {
            api.logging().logToError("Exception in parseSitemapDescriptors: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showStatusMessage("Error during descriptors parsing: " + e.getMessage(), Color.RED);
            });
        }
    }

    /**
     * Process a JavaScript response to extract Apex descriptors and their parameters
     */
    private void processJavaScriptResponseForDescriptors(HttpRequestResponse jsResponse, String sessionTimestamp) {
        if (jsResponse == null || jsResponse.response() == null) {
            return;
        }

        try {
            String responseBody = jsResponse.response().bodyToString();
            String sourceUrl = jsResponse.request().url();

            // Keep track of processed descriptors to avoid duplicates
            java.util.Set<String> processedInThisResponse = new java.util.HashSet<>();

            // First pass: Find descriptors with their parameter definitions using enhanced pattern
            Matcher contextMatcher = DESCRIPTOR_CONTEXT_PATTERN.matcher(responseBody);
            while (contextMatcher.find()) {
                String descriptor = contextMatcher.group(1);
                String parameterArrayJson = contextMatcher.group(2);

                if (descriptor != null && discoveredDescriptors.add(descriptor)) {
                    processedInThisResponse.add(descriptor);

                    // Parse parameters if available
                    java.util.List<DescriptorInfo.ParameterInfo> parameters = new java.util.ArrayList<>();
                    if (parameterArrayJson != null && !parameterArrayJson.trim().isEmpty()) {
                        parameters = parseParametersFromJson(parameterArrayJson);
                    }

                    // Create descriptor info
                    DescriptorInfo descriptorInfo = new DescriptorInfo(descriptor, parameters, sourceUrl);
                    addDescriptorToResults(descriptorInfo, sessionTimestamp);
                }
            }

            // Second pass: Find descriptors without immediate parameter context, but search for parameters
            Matcher simpleMatcher = DESCRIPTOR_SIMPLE_PATTERN.matcher(responseBody);
            while (simpleMatcher.find()) {
                String descriptor = simpleMatcher.group(1);

                if (descriptor != null && !processedInThisResponse.contains(descriptor) && discoveredDescriptors.add(descriptor)) {
                    // Try to find parameters for this descriptor elsewhere in the response
                    java.util.List<DescriptorInfo.ParameterInfo> parameters = findParametersForDescriptor(responseBody, descriptor);

                    // Create descriptor info
                    DescriptorInfo descriptorInfo = new DescriptorInfo(descriptor, parameters, sourceUrl);
                    addDescriptorToResults(descriptorInfo, sessionTimestamp);
                }
            }

        } catch (Exception e) {
            api.logging().logToError("Exception processing JavaScript response for descriptors: " + e.getMessage());
        }
    }

    /**
     * Find parameters for a specific descriptor in the response body
     */
    private java.util.List<DescriptorInfo.ParameterInfo> findParametersForDescriptor(String responseBody, String targetDescriptor) {
        java.util.List<DescriptorInfo.ParameterInfo> parameters = new java.util.ArrayList<>();

        try {
            // Escape the descriptor for regex search
            String escapedDescriptor = Pattern.quote(targetDescriptor);

            // Create a pattern to find parameter arrays associated with this descriptor
            // Look for patterns like: "descriptor":"apex://...", ... "pa":[...]
            Pattern descriptorWithParamsPattern = Pattern.compile(
                "\"descriptor\"\\s*:\\s*\"" + escapedDescriptor + "\"[^}]*?\"pa\"\\s*:\\s*(\\[[^\\]]*\\])",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            Matcher matcher = descriptorWithParamsPattern.matcher(responseBody);
            while (matcher.find()) {
                String parameterArrayJson = matcher.group(1);
                if (parameterArrayJson != null && !parameterArrayJson.trim().isEmpty()) {
                    java.util.List<DescriptorInfo.ParameterInfo> foundParams = parseParametersFromJson(parameterArrayJson);
                    parameters.addAll(foundParams);
                }
            }

            // If no parameters found with the primary pattern, try alternative approaches
            if (parameters.isEmpty()) {
                // Look for the descriptor in action arrays and extract parameters
                // Pattern: "ac":[...{"descriptor":"target","pa":[...]}...]
                Pattern actionArrayPattern = Pattern.compile(
                    "\"ac\"\\s*:\\s*\\[[^\\]]*?\\{[^}]*?\"descriptor\"\\s*:\\s*\"" + escapedDescriptor + "\"[^}]*?\"pa\"\\s*:\\s*(\\[[^\\]]*\\])",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL
                );

                Matcher actionMatcher = actionArrayPattern.matcher(responseBody);
                while (actionMatcher.find()) {
                    String parameterArrayJson = actionMatcher.group(1);
                    if (parameterArrayJson != null && !parameterArrayJson.trim().isEmpty()) {
                        java.util.List<DescriptorInfo.ParameterInfo> foundParams = parseParametersFromJson(parameterArrayJson);
                        parameters.addAll(foundParams);
                    }
                }
            }

        } catch (Exception e) {
            api.logging().logToError("Error finding parameters for descriptor " + targetDescriptor + ": " + e.getMessage());
        }

        return parameters;
    }

    /**
     * Parse parameter definitions from JSON parameter array
     */
    private java.util.List<DescriptorInfo.ParameterInfo> parseParametersFromJson(String parameterArrayJson) {
        java.util.List<DescriptorInfo.ParameterInfo> parameters = new java.util.ArrayList<>();

        try {
            // Extract individual parameter objects using regex
            Matcher paramMatcher = PARAMETER_PATTERN.matcher(parameterArrayJson);
            while (paramMatcher.find()) {
                String name = paramMatcher.group(1);
                String type = paramMatcher.group(2);

                if (name != null && type != null) {
                    parameters.add(new DescriptorInfo.ParameterInfo(name, type));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error parsing parameter definitions: " + e.getMessage());
        }

        return parameters;
    }

    /**
     * Generate sample JSON value based on Apex type
     */
    private String generateSampleValue(String apexType) {
        if (apexType == null) {
            return "\"sample\"";
        }

        String lowerType = apexType.toLowerCase();

        if (lowerType.contains("string")) {
            return "\"sample\"";
        } else if (lowerType.contains("integer") || lowerType.contains("int")) {
            return "123";
        } else if (lowerType.contains("boolean") || lowerType.contains("bool")) {
            return "true";
        } else if (lowerType.contains("decimal") || lowerType.contains("double") || lowerType.contains("float")) {
            return "123.45";
        } else if (lowerType.contains("date")) {
            return "\"2024-01-01\"";
        } else if (lowerType.contains("list") || lowerType.contains("array")) {
            return "[\"sample\"]";
        } else {
            // Default to string for unknown types
            return "\"sample\"";
        }
    }

    /**
     * Generate sample message JSON for the descriptor
     */
    private String generateSampleMessage(DescriptorInfo descriptorInfo) {
        try {
            StringBuilder paramsBuilder = new StringBuilder();
            paramsBuilder.append("{");

            boolean first = true;
            for (DescriptorInfo.ParameterInfo param : descriptorInfo.getParameters()) {
                if (!first) {
                    paramsBuilder.append(",");
                }
                paramsBuilder.append("\"").append(param.getName()).append("\":");
                paramsBuilder.append(generateSampleValue(param.getType()));
                first = false;
            }

            paramsBuilder.append("}");

            // Create the complete sample message
            String sampleMessage = String.format(
                "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"%s\",\"callingDescriptor\":\"UNKNOWN\",\"params\":%s}]}",
                descriptorInfo.getDescriptor(),
                paramsBuilder.toString()
            );

            return sampleMessage;
        } catch (Exception e) {
            api.logging().logToError("Error generating sample message: " + e.getMessage());
            return "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"" + descriptorInfo.getDescriptor() + "\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{}}]}";
        }
    }

    /**
     * Add discovered descriptor to results with formatted display
     */
    private void addDescriptorToResults(DescriptorInfo descriptorInfo, String sessionTimestamp) {
        if (descriptorInfo == null || currentDescriptorResults == null) {
            return;
        }

        // === Category 1: Simple List - Just descriptor names ===
        String listCategoryName = "Apex Descriptors List (" + sessionTimestamp + ")";
        java.util.List<String> listEntries = currentDescriptorResults.getRoutesForCategory(listCategoryName);
        if (listEntries == null) {
            listEntries = new java.util.ArrayList<>();
        } else {
            listEntries = new java.util.ArrayList<>(listEntries); // Create mutable copy
        }

        // Add just the descriptor name to the simple list
        listEntries.add(descriptorInfo.getDescriptor());
        currentDescriptorResults.addRouteCategory(listCategoryName, listEntries);

        // === Category 2: Detailed Information with separators ===
        String detailsCategoryName = "Apex Descriptors Details (" + sessionTimestamp + ")";
        java.util.List<String> detailEntries = currentDescriptorResults.getRoutesForCategory(detailsCategoryName);
        if (detailEntries == null) {
            detailEntries = new java.util.ArrayList<>();
        } else {
            detailEntries = new java.util.ArrayList<>(detailEntries); // Create mutable copy
        }

        // Format parameters for display as JSON array
        String paramsDisplay;
        if (descriptorInfo.getParameters().isEmpty()) {
            paramsDisplay = "No parameters";
        } else {
            StringBuilder paramsBuilder = new StringBuilder();
            paramsBuilder.append("[");
            for (int i = 0; i < descriptorInfo.getParameters().size(); i++) {
                DescriptorInfo.ParameterInfo param = descriptorInfo.getParameters().get(i);
                if (i > 0) {
                    paramsBuilder.append(",");
                }
                paramsBuilder.append("{\"name\":\"").append(param.getName())
                           .append("\",\"type\":\"").append(param.getType()).append("\"}");
            }
            paramsBuilder.append("]");
            paramsDisplay = paramsBuilder.toString();
        }

        // Generate sample message
        String sampleMessage = generateSampleMessage(descriptorInfo);

        // Create separator for visual distinction between entries
        String separator = "================================================================================";

        // Format the complete detailed entry with separator
        String detailEntry;
        if (detailEntries.isEmpty()) {
            // First entry - no leading separator
            detailEntry = String.format(
                "Descriptor:\n%s\n\nParameters:\n%s\n\nSample Message:\n%s",
                descriptorInfo.getDescriptor(),
                paramsDisplay,
                sampleMessage
            );
        } else {
            // Subsequent entries - add separator before
            detailEntry = String.format(
                "%s\n\nDescriptor:\n%s\n\nParameters:\n%s\n\nSample Message:\n%s",
                separator,
                descriptorInfo.getDescriptor(),
                paramsDisplay,
                sampleMessage
            );
        }

        detailEntries.add(detailEntry);
        currentDescriptorResults.addRouteCategory(detailsCategoryName, detailEntries);

        api.logging().logToOutput("Found Apex descriptor: " + descriptorInfo.getDescriptor() + " with " + descriptorInfo.getParameters().size() + " parameters");
    }

    /**
     * Process a JavaScript response to extract meaningful paths
     */
    private void processJavaScriptResponseForPaths(HttpRequestResponse jsResponse, BaseRequest baseRequest, String sessionTimestamp) {
        if (jsResponse == null || jsResponse.response() == null) {
            return;
        }

        try {
            String responseBody = jsResponse.response().bodyToString();
            String sourceUrl = jsResponse.request().url();

            // Extract the base domain for absolute URL filtering
            String baseDomain = null;
            try {
                java.net.URI uri = new java.net.URI(sourceUrl);
                baseDomain = uri.getHost();
            } catch (Exception e) {
                api.logging().logToOutput("Could not parse source URL for domain extraction: " + sourceUrl);
            }

            // Extract relative paths (starting with /, ./, ../)
            Matcher relativeMatcher = JS_RELATIVE_PATH_PATTERN.matcher(responseBody);
            while (relativeMatcher.find()) {
                String path = relativeMatcher.group(1);
                if (isValidJSPath(path)) {
                    addJSPathToResults(path, "Relative Path", jsResponse, sessionTimestamp);
                }
            }

            // Extract parameterized paths (with placeholders like {id})
            Matcher paramMatcher = JS_PARAMETERIZED_PATH_PATTERN.matcher(responseBody);
            while (paramMatcher.find()) {
                String path = paramMatcher.group(1);
                if (isValidJSPath(path)) {
                    addJSPathToResults(path, "Parameterized Path", jsResponse, sessionTimestamp);
                }
            }

            // Extract absolute URLs and filter for same domain
            if (baseDomain != null) {
                Matcher urlMatcher = JS_URL_PATH_PATTERN.matcher(responseBody);
                while (urlMatcher.find()) {
                    String fullUrl = urlMatcher.group(1);
                    String urlPath = urlMatcher.group(2);

                    try {
                        java.net.URI fullUri = new java.net.URI(fullUrl);
                        // Only include URLs from the same domain
                        if (baseDomain.equalsIgnoreCase(fullUri.getHost()) && urlPath != null && isValidJSPath(urlPath)) {
                            addJSPathToResults(urlPath, "Same-Domain Path", jsResponse, sessionTimestamp);
                        }
                    } catch (Exception e) {
                        // Skip malformed URLs
                        continue;
                    }
                }
            }

        } catch (Exception e) {
            api.logging().logToError("Exception processing JavaScript response for paths: " + e.getMessage());
        }
    }

    /**
     * Validate if a discovered path is meaningful and should be included
     */
    private boolean isValidJSPath(String path) {
        if (path == null || path.trim().isEmpty()) {
            return false;
        }

        path = path.trim();

        // Exclude paths containing quotes
        if (path.contains("'") || path.contains("\"")) {
            return false;
        }

        // Exclude obvious non-paths
        if (path.length() < 2 || path.equals("/") || path.equals("./") || path.equals("../")) {
            return false;
        }

        // Exclude regex patterns and JavaScript code patterns
        if (JS_EXCLUDE_PATTERN.matcher(path).matches()) {
            return false;
        }

        // Exclude common non-path patterns
        if (path.matches(".*\\b(function|var|let|const|return|if|else|for|while|switch|case)\\b.*")) {
            return false;
        }

        // Exclude data URLs and javascript URLs
        if (path.toLowerCase().startsWith("data:") || path.toLowerCase().startsWith("javascript:")) {
            return false;
        }

        // Must look like a path (contain at least one meaningful character)
        if (!path.matches(".*[a-zA-Z0-9_-].*")) {
            return false;
        }

        // Exclude common asset file extensions (images, fonts, stylesheets, maps)
        String lowerPath = path.toLowerCase();
        String[] excludedExtensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".css", ".map", ".pdf", ".webp",
            ".avif", ".tiff", ".tif", ".webm", ".mp4", ".avi", ".mov", ".wmv"};
        for (String ext : excludedExtensions) {
            if (lowerPath.endsWith(ext)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Add a discovered JS path to the results, handling duplicates
     */
    private void addJSPathToResults(String path, String pathType, HttpRequestResponse sourceResponse, String sessionTimestamp) {
        if (path == null || discoveredJSPaths.contains(path) || !isValidPath(path)) {
            return; // Skip duplicates and invalid paths
        }

        // Add to discovered set
        discoveredJSPaths.add(path);

        // Add to results by category - use timestamped category name for all paths
        if (currentJSPathsResults != null) {
            String categoryName = "Potential Paths (" + sessionTimestamp + ")";

            // Get existing routes for this category, or create new list
            java.util.List<String> existingRoutes = currentJSPathsResults.getRoutesForCategory(categoryName);
            if (existingRoutes == null) {
                existingRoutes = new java.util.ArrayList<>();
            } else {
                existingRoutes = new java.util.ArrayList<>(existingRoutes); // Create mutable copy
            }

            // Add the new path (clean, without source info)
            existingRoutes.add(path);

            // Update the category
            currentJSPathsResults.addRouteCategory(categoryName, existingRoutes);

            api.logging().logToOutput("Found JS path: " + path + " (" + pathType + ")");
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
            
            // Send the request with preserved HTTP version
            api.logging().logToOutput("Sending specific object request to: " + originalRequest.url());
            HttpRequestResponse response = sendRequestWithPreservedHttpVersion(specificObjectRequest, baseRequest);
            
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
            // Initialize the ObjectByNameResult for this tab (or use existing if appending)
            if (!tabObjectResults.containsKey(tabId)) {
                // New tab - create fresh results
                tabObjectResults.put(tabId, new ObjectByNameResult());
            }
            // If tab already exists, keep existing results for appending

            // Create/update the tab immediately with the final tab title
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
                    HttpRequestResponse response = sendRequestWithPreservedHttpVersion(specificObjectRequest, baseRequest);
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
            // Initialize the ObjectByNameResult for this tab (or use existing if appending)
            if (!tabObjectResults.containsKey(tabId)) {
                // New tab - create fresh results
                tabObjectResults.put(tabId, new ObjectByNameResult());
            }
            // If tab already exists, keep existing results for appending

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
                    HttpRequestResponse response = sendRequestWithPreservedHttpVersion(specificObjectRequest, baseRequest);
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

                    // Debug logging to understand response format
                    api.logging().logToOutput("Wordlist scan - checking object: " + objectName);
                    api.logging().logToOutput("Response contains success:true: " + responseBody.contains("\"success\":true"));
                    api.logging().logToOutput("Response contains INVALID_TYPE: " + responseBody.contains("INVALID_TYPE"));

                    // Try to parse the response to see if it contains actual data
                    boolean hasValidData = false;
                    try {
                        // Use the same parsing logic as the incremental parser to check for valid data
                        ObjectMapper mapper = new ObjectMapper();
                        JsonNode rootNode = mapper.readTree(responseBody);
                        JsonNode actionsNode = rootNode.path("actions");

                        if (actionsNode.isArray() && actionsNode.size() > 0) {
                            JsonNode firstAction = actionsNode.get(0);
                            JsonNode returnValue = firstAction.path("returnValue");
                            JsonNode resultArray = returnValue.path("result");

                            // Check if we have actual result data (not just empty array)
                            if (resultArray.isArray() && resultArray.size() > 0) {
                                hasValidData = true;
                                api.logging().logToOutput("Found valid data for object: " + objectName + " (records: " + resultArray.size() + ")");
                            }
                        }
                    } catch (Exception e) {
                        api.logging().logToOutput("Error parsing response for object " + objectName + ": " + e.getMessage());
                    }

                    // Use either the original condition OR the new data validation
                    if ((responseBody.contains("\"success\":true") && !responseBody.contains("INVALID_TYPE")) || hasValidData) {
                        foundObjects[0]++;

                        // Parse and immediately add to tab
                        parseBulkObjectResponseIncremental(responseBody, tabId, objectName, baseRequest.getId());

                        api.logging().logToOutput("Added object to tab: " + objectName);
                    } else {
                        api.logging().logToOutput("Skipped object (no valid data): " + objectName);
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
     * Perform record retrieval by modifying the request with getRecord action
     */
    private void performRecordRetrieval(BaseRequest baseRequest, String resultId, String recordId) {
        api.logging().logToOutput("Starting record retrieval for ID: " + recordId);

        try {
            // Escape the record ID for JSON
            String escapedRecordId = recordId.replace("\\", "\\\\").replace("\"", "\\\"");

            // Create the record retrieval payload with the specified format
            String recordPayload = String.format(
                "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"recordId\":\"%s\",\"record\":null,\"inContextOfComponent\":\"\",\"mode\":\"VIEW\",\"layoutType\":\"FULL\",\"defaultFieldValues\":null,\"navigationLocation\":\"LIST_VIEW_ROW\"}}]}",
                escapedRecordId
            );

            // Create a modified request with the record retrieval payload in the message parameter
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();
            HttpRequest recordRequest = modifyMessageParameter(originalRequest, recordPayload);

            // Send the request with preserved HTTP version
            api.logging().logToOutput("Sending record retrieval request to: " + originalRequest.url());
            HttpRequestResponse response = sendRequestWithPreservedHttpVersion(recordRequest, baseRequest);

            if (response.response() == null) {
                throw new RuntimeException("No response received");
            }

            // Parse the response to extract record data
            String responseBody = response.response().bodyToString();
            api.logging().logToOutput("Record retrieval response received, parsing data...");

            // Create the result content for the tab
            String resultContent = formatRecordRetrievalResult(recordId, responseBody);

            // Create the result tab with request information
            SwingUtilities.invokeLater(() -> {
                resultTabCallback.createRecordTab(resultId, recordId, resultContent, baseRequest);
                clearBusyState();
                showStatusMessage("✓ Record retrieved successfully: " + recordId, Color.GREEN);
            });

        } catch (Exception e) {
            api.logging().logToError("Record retrieval failed: " + e.getMessage());
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Record retrieval failed: " + e.getMessage());
            });
            throw e;
        }
    }

    /**
     * Format the record retrieval result for display
     */
    private String formatRecordRetrievalResult(String recordId, String responseBody) {
        StringBuilder result = new StringBuilder();
        result.append("Record ID: ").append(recordId).append("\n");
        result.append("Retrieved at: ").append(java.time.LocalDateTime.now().toString()).append("\n");
        result.append("==========================================\n\n");

        try {
            // Parse JSON response for better formatting
            ObjectMapper mapper = new ObjectMapper();
            Object jsonObject = mapper.readValue(responseBody, Object.class);
            String prettyJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonObject);
            result.append("Response Data:\n").append(prettyJson);
        } catch (Exception e) {
            // If JSON parsing fails, just show raw response
            result.append("Raw Response:\n").append(responseBody);
        }

        return result.toString();
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
     * Send HTTP request while being aware of HTTP version compatibility.
     * This logs HTTP version information to help diagnose 400 Bad Request errors
     * that can occur when there are HTTP version mismatches.
     */
    private HttpRequestResponse sendRequestWithPreservedHttpVersion(HttpRequest modifiedRequest, BaseRequest baseRequest) {
        try {
            // Get the original request to check HTTP version
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();
            String originalHttpVersion = originalRequest.httpVersion();
            String modifiedHttpVersion = modifiedRequest.httpVersion();

            api.logging().logToOutput("HTTP Version Check - Original: " + originalHttpVersion +
                                    ", Modified: " + modifiedHttpVersion);

            // Log HTTP version mismatch for debugging
            if (!originalHttpVersion.equals(modifiedHttpVersion)) {
                api.logging().logToOutput("WARNING: HTTP version mismatch detected! " +
                                        "Original: " + originalHttpVersion +
                                        ", Modified: " + modifiedHttpVersion +
                                        ". This may cause 400 Bad Request errors.");
                api.logging().logToOutput("If you encounter 400 errors, this HTTP version mismatch may be the cause.");
            }

            // Send the request - let Montoya API handle HTTP version automatically
            // The API should negotiate the appropriate version based on the connection
            return api.http().sendRequest(modifiedRequest);

        } catch (Exception e) {
            api.logging().logToError("Error during HTTP version-aware request sending: " + e.getMessage());
            // Fallback to direct send
            return api.http().sendRequest(modifiedRequest);
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
     * Parse the route discovery response to extract navigation items and content URLs
     */
    private void parseRouteDiscoveryResponse(String responseBody, String resultId, int requestId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);

            // Navigate to actions[0].returnValue.navItems
            JsonNode actionsNode = rootNode.path("actions");
            if (!actionsNode.isArray() || actionsNode.size() == 0) {
                throw new RuntimeException("Invalid response format: no actions array");
            }

            JsonNode firstAction = actionsNode.get(0);
            String state = firstAction.path("state").asText();

            if (!"SUCCESS".equals(state)) {
                throw new RuntimeException("Route discovery request failed with state: " + state);
            }

            JsonNode returnValue = firstAction.path("returnValue");
            JsonNode navItemsNode = returnValue.path("navItems");

            if (navItemsNode.isMissingNode() || !navItemsNode.isArray()) {
                throw new RuntimeException("No navItems array found in response");
            }

            // Extract content URLs from navItems
            java.util.List<String> contentUrls = new java.util.ArrayList<>();

            for (JsonNode navItem : navItemsNode) {
                JsonNode contentNode = navItem.path("content");
                if (!contentNode.isMissingNode() && !contentNode.asText().trim().isEmpty()) {
                    String contentUrl = contentNode.asText().trim();
                    if (!contentUrl.equals("null")) { // Also check for string "null"
                        contentUrls.add(contentUrl);
                    }
                }
            }

            // Create RouteDiscoveryResult
            RouteDiscoveryResult routeDiscoveryResult = new RouteDiscoveryResult();

            // Add category with timestamp and request info
            String timestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            String categoryName = "Retrieved Nav Items (request" + requestId + "-" +
                timestamp.replace(" ", "-").replace(":", "-") + ")";

            routeDiscoveryResult.addRouteCategory(categoryName, contentUrls);

            api.logging().logToOutput("Route discovery parsed: " + contentUrls.size() + " navigation items found");

            // Update UI on EDT
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                // Create or update result tab
                resultTabCallback.updateDiscoveredRoutesTab(resultId, routeDiscoveryResult);
                showStatusMessage("✓ Route discovery completed: " + contentUrls.size() + " navigation items found", Color.GREEN);

                api.logging().logToOutput("Route discovery completed successfully:");
                api.logging().logToOutput("  Navigation items found: " + contentUrls.size());
                api.logging().logToOutput("  Category: " + categoryName);
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Failed to parse route discovery response: " + e.getMessage());
            });
            throw new RuntimeException("Failed to parse route discovery response", e);
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
                jsonContent.append("Records found in ").append(objectName).append(" object: ").append(resultArray.size()).append("\n\n");
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


            // Add the object entry to the tab's ObjectByNameResult (like other operations)
            SwingUtilities.invokeLater(() -> {
                // Initialize the ObjectByNameResult for this tab (or use existing if appending)
                if (!tabObjectResults.containsKey(resultId)) {
                    // New tab - create fresh results
                    tabObjectResults.put(resultId, new ObjectByNameResult());
                }

                // Add entry to the tab's results
                ObjectByNameResult tabResult = tabObjectResults.get(resultId);
                api.logging().logToOutput("TabResult from tabObjectResults: " + (tabResult != null ? "not null" : "NULL"));
                if (tabResult != null) {
                    tabResult.addObjectEntry(objectEntryName, jsonData);
                    // Update the tab content
                    api.logging().logToOutput("About to call resultTabCallback.createObjectByNameTab - resultId: " + resultId);
                    api.logging().logToOutput("TabResult object entries: " + tabResult.getObjectEntries().size());
                    resultTabCallback.createObjectByNameTab(resultId, tabResult);
                    api.logging().logToOutput("Called resultTabCallback.createObjectByNameTab successfully");
                }

                clearBusyState();

                if (resultArray.size() == 0) {
                    showStatusMessage("✗ No results found for object '" + objectName + "' - " + resultId, Color.ORANGE);
                    api.logging().logToOutput("No data found for object: " + objectName);
                } else {
                    showStatusMessage("✓ Found " + resultArray.size() + " records for object '" + objectName + "' - " + resultId, Color.GREEN);
                    api.logging().logToOutput("Specific object search completed successfully:");
                    api.logging().logToOutput("  Object: " + objectName);
                    api.logging().logToOutput("  Records found in " + objectName + " object: " + resultArray.size());
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
                jsonContent.append("Records found in ").append(objectName).append(" object: ").append(resultArray.size()).append("\n\n");
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
                jsonContent.append("Records found in ").append(objectName).append(" object: ").append(resultArray.size()).append("\n\n");
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
            
            int result = fileChooser.showOpenDialog(api.userInterface().swingUtils().suiteFrame());
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
        getRecordByIdBtn.addActionListener(e -> executeAction("GetRecordById"));
        getNavItemsBtn.addActionListener(e -> executeAction("GetNavItems"));
        getRouterInitializerPathsBtn.addActionListener(e -> executeAction("GetRouterInitializerPaths"));
        getPotentialPathsFromJSBtn.addActionListener(e -> executeAction("GetPotentialPathsFromJS"));
        findDescriptorsFromSitemapBtn.addActionListener(e -> executeAction("FindDescriptorsFromSitemap"));
        performAllSitemapSearchesBtn.addActionListener(e -> executeAction("PerformAllSitemapSearches"));

        // Record ID field handler - enable/disable button based on text content
        recordIdField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateRecordButtonState();
            }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateRecordButtonState();
            }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateRecordButtonState();
            }

            private void updateRecordButtonState() {
                boolean hasText = !recordIdField.getText().trim().isEmpty();
                boolean hasRequests = hasRequests();
                getRecordByIdBtn.setEnabled(hasText && hasRequests && !isProcessing);
            }
        });

        // Cancel button handler
        cancelBtn.addActionListener(e -> {
            api.logging().logToOutput("Operation cancelled by user - stopping all requests");
            operationCancelled = true; // Set cancellation flag immediately
            routerPathsCancelled = true; // Cancel router paths parsing if in progress
            jsPathsCancelled = true; // Cancel JS paths parsing if in progress
            descriptorsCancelled = true; // Cancel descriptors parsing if in progress

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

        // Check if this is a passive operation that doesn't require a baseline request
        boolean isPassiveOperation = "GetRouterInitializerPaths".equals(actionType) ||
                                   "GetPotentialPathsFromJS".equals(actionType) ||
                                   "FindDescriptorsFromSitemap".equals(actionType) ||
                                   "PerformAllSitemapSearches".equals(actionType);

        if (selectedItem == null && !isPassiveOperation) {
            return;
        }

        final BaseRequest selectedRequest = (selectedItem != null) ? selectedItem.getBaseRequest() : null;

        String objectName = objectNameField.getText().trim();

        // Log the action (placeholder for actual implementation)
        if (selectedRequest != null) {
            api.logging().logToOutput("Executing action: " + actionType +
                                    " on request ID: " + selectedRequest.getId());
        } else {
            api.logging().logToOutput("Executing passive action: " + actionType +
                                    " (no baseline request required)");
        }
        
        switch (actionType) {
            case "FindAllObjectNames":
                setBusyState(findAllObjectNamesBtn, "Object Discovery");
                // Generate result ID
                String discoverResultId = generateDiscoverResultId(selectedRequest.getId());
                
                // Perform object discovery in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        performObjectDiscovery(selectedRequest, discoverResultId);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during object discovery: " + e.getMessage());
                            api.logging().logToError("Object discovery failed: " + e.getMessage());
                        });
                    }
                }, "ObjectDiscovery-" + discoverResultId).start();
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
                currentOperationThread = ThreadManager.createManagedThread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, tabId, discoveredDefaultObjects, "default objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during default objects retrieval: " + e.getMessage());
                            api.logging().logToError("Default objects retrieval failed: " + e.getMessage());
                        });
                    }
                }, "BulkObjectRetrieval-Default-" + tabId);
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
                currentOperationThread = ThreadManager.createManagedThread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, customTabId, discoveredCustomObjects, "custom objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during custom objects retrieval: " + e.getMessage());
                            api.logging().logToError("Custom objects retrieval failed: " + e.getMessage());
                        });
                    }
                }, "BulkObjectRetrieval-Custom-" + customTabId);
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
                currentOperationThread = ThreadManager.createManagedThread(() -> {
                    try {
                        performBulkObjectRetrieval(selectedRequest, allTabId, allDiscoveredObjects, "all objects");
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during all objects retrieval: " + e.getMessage());
                            api.logging().logToError("All objects retrieval failed: " + e.getMessage());
                        });
                    }
                }, "BulkObjectRetrieval-All-" + allTabId);
                currentOperationThread.start();
                break;
            case "FindObjectByName":
                if (objectName.isEmpty()) {
                    showErrorMessage("Please enter an object name to search for.");
                    return;
                }

                // Ask user about tab choice before starting object search
                String objByNameResultId = getUserTabChoiceForBulkRetrieval("object '" + objectName + "'", 1);
                if (objByNameResultId == null) {
                    return; // User cancelled
                }

                setBusyState(findObjectByNameBtn, "Getting Object by Name");

                // Perform specific object search in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        performSpecificObjectSearch(selectedRequest, objByNameResultId, objectName);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during specific object search: " + e.getMessage());
                            api.logging().logToError("Specific object search failed: " + e.getMessage());
                        });
                    }
                }, "SpecificObjectSearch-" + objectName).start();
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
                currentOperationThread = ThreadManager.createManagedThread(() -> {
                    try {
                        performWordlistScan(selectedRequest, wordlistResultId, wordlistSource);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBulkRetrievalState();
                            showErrorMessage("Error during wordlist scan: " + e.getMessage());
                            api.logging().logToError("Wordlist scan failed: " + e.getMessage());
                        });
                    }
                }, "WordlistScan-" + wordlistResultId);
                currentOperationThread.start();
                break;
            case "GetRecordById":
                String recordId = recordIdField.getText().trim();
                if (recordId.isEmpty()) {
                    showErrorMessage("Please enter a record ID.");
                    return;
                }

                // Ask user about tab choice before starting record retrieval
                String recordResultId = getUserTabChoiceForRecordRetrieval(recordId);
                if (recordResultId == null) {
                    return; // User cancelled
                }

                setBusyState(getRecordByIdBtn, "Getting Record");

                api.logging().logToOutput("Retrieving record with ID: " + recordId);

                // Perform record retrieval in background thread
                currentOperationThread = ThreadManager.createManagedThread(() -> {
                    try {
                        performRecordRetrieval(selectedRequest, recordResultId, recordId);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during record retrieval: " + e.getMessage());
                            api.logging().logToError("Record retrieval failed: " + e.getMessage());
                        });
                    }
                }, "RecordRetrieval-" + recordId);
                currentOperationThread.start();
                break;
            case "GetNavItems":
                setBusyState(getNavItemsBtn, "Route Discovery");

                // Generate result ID for route discovery with tab reuse check
                String routeResultId = generateRouteDiscoveryResultIdWithReuseCheck();

                api.logging().logToOutput("Starting route discovery...");

                // Perform route discovery in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        performRouteDiscovery(selectedRequest, routeResultId);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during route discovery: " + e.getMessage());
                            api.logging().logToError("Route discovery failed: " + e.getMessage());
                        });
                    }
                }, "RouteDiscovery-" + routeResultId).start();
                break;
            case "GetRouterInitializerPaths":
                setBusyState(getRouterInitializerPathsBtn, "Sitemap Router Paths Parsing");

                // Generate result ID for sitemap router paths parsing with tab reuse check
                String routerInitResultId = generateRouteDiscoveryResultIdWithReuseCheck();

                api.logging().logToOutput("Starting passive sitemap router paths parsing...");

                // Check sitemap only checkbox state
                boolean sitemapOnlyRouter = searchSitemapOnlyCheckbox.isSelected();

                // Perform passive sitemap router paths parsing in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        parseSitemapRouterPaths(selectedRequest, routerInitResultId, sitemapOnlyRouter);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during sitemap router paths parsing: " + e.getMessage());
                            api.logging().logToError("Sitemap router paths parsing failed: " + e.getMessage());
                        });
                    }
                }, "RouterInitializerPaths-" + routerInitResultId).start();
                break;
            case "GetPotentialPathsFromJS":
                setBusyState(getPotentialPathsFromJSBtn, "Sitemap JS Paths Parsing");

                // Generate result ID for sitemap JS paths parsing with tab reuse check
                String jsPathsResultId = generateRouteDiscoveryResultIdWithReuseCheck();

                api.logging().logToOutput("Starting passive sitemap JS paths parsing...");

                // Check sitemap only checkbox state
                boolean sitemapOnlyJS = searchSitemapOnlyCheckbox.isSelected();

                // Perform passive sitemap JS paths parsing in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        parseSitemapJSPaths(selectedRequest, jsPathsResultId, sitemapOnlyJS);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during sitemap JS paths parsing: " + e.getMessage());
                            api.logging().logToError("Sitemap JS paths parsing failed: " + e.getMessage());
                        });
                    }
                }, "PotentialPathsFromJS-" + jsPathsResultId).start();
                break;
            case "FindDescriptorsFromSitemap":
                setBusyState(findDescriptorsFromSitemapBtn, "Sitemap Descriptors Parsing");

                // Generate result ID for sitemap descriptors parsing with tab reuse check
                String descriptorsResultId = generateRouteDiscoveryResultIdWithReuseCheck();

                api.logging().logToOutput("Starting passive sitemap descriptors parsing...");

                // Check sitemap only checkbox state
                boolean sitemapOnlyDescriptors = searchSitemapOnlyCheckbox.isSelected();

                // Perform passive sitemap descriptors parsing in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        parseSitemapDescriptors(selectedRequest, descriptorsResultId, sitemapOnlyDescriptors);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during sitemap descriptors parsing: " + e.getMessage());
                            api.logging().logToError("Sitemap descriptors parsing failed: " + e.getMessage());
                        });
                    }
                }, "DescriptorsFromSitemap-" + descriptorsResultId).start();
                break;

            case "PerformAllSitemapSearches":
                setBusyState(performAllSitemapSearchesBtn, "All Sitemap Searches");

                api.logging().logToOutput("Starting all passive sitemap searches...");

                // Check sitemap only checkbox state
                boolean sitemapOnlyAll = searchSitemapOnlyCheckbox.isSelected();

                // Perform all sitemap searches in background thread
                ThreadManager.createManagedThread(() -> {
                    try {
                        performAllSitemapSearches(selectedRequest, sitemapOnlyAll);
                    } catch (Exception e) {
                        SwingUtilities.invokeLater(() -> {
                            clearBusyState();
                            showErrorMessage("Error during all sitemap searches: " + e.getMessage());
                            api.logging().logToError("All sitemap searches failed: " + e.getMessage());
                        });
                    }
                }, "AllSitemapSearches").start();
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

        // Active route discovery (requires HTTP requests) depends on having baseline requests
        getNavItemsBtn.setEnabled(hasRequests);

        // Passive route discovery buttons (sitemap parsing) don't require baseline requests
        getRouterInitializerPathsBtn.setEnabled(true);
        getPotentialPathsFromJSBtn.setEnabled(true);
        findDescriptorsFromSitemapBtn.setEnabled(true);
        performAllSitemapSearchesBtn.setEnabled(true);

        // Get Record by ID depends on both having requests and non-empty record ID
        updateRecordByIdButtonState();

        // Other UI elements
        objectNameField.setEnabled(hasRequests);
        recordIdField.setEnabled(hasRequests);
        requestSelector.setEnabled(hasRequests);
        usePresetWordlistCheckbox.setEnabled(hasRequests);
        selectWordlistBtn.setEnabled(hasRequests && !usePresetWordlistCheckbox.isSelected());

        // These controls should be enabled regardless of baseline request availability
        threadCountSpinner.setEnabled(true);
        alwaysCreateNewTabCheckbox.setEnabled(true);

        // Discovery result selector depends on having discovery results
        discoveryResultSelector.setEnabled(hasRequests && hasDiscoveryResults);
        
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

    private void updateRecordByIdButtonState() {
        boolean hasRequests = !baseRequests.isEmpty();
        boolean hasText = !recordIdField.getText().trim().isEmpty();
        getRecordByIdBtn.setEnabled(hasRequests && hasText && !isProcessing);
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
     * Base class for result panels with shared toolbar functionality
     */
    public static abstract class BaseResultPanel extends JPanel {
        // Toolbar components
        protected JTextField searchField;
        protected JTextField filterField;
        protected JCheckBox searchRegexCheckBox;
        protected JCheckBox filterRegexCheckBox;
        protected JCheckBox hideEmptyCheckBox;
        protected JButton searchNextBtn;
        protected JButton searchPrevBtn;
        protected JButton resetBtn;
        protected JButton exportBtn;
        protected JLabel searchStatusLabel;

        // Search state
        protected int currentSearchIndex = -1;
        protected List<Integer> searchMatches = new ArrayList<>();
        protected String lastSearchText = "";
        protected int lastCursorPosition = 0;

        /**
         * Create the shared toolbar with all common functionality
         */
        protected JPanel createSharedToolbar() {
            JPanel toolbar = new JPanel(new BorderLayout());
            toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

            // Left panel: Export and Search controls
            JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));

            // Export button first
            this.exportBtn = new JButton("Export");
            exportBtn.setToolTipText("Export filtered results to text files in a selected folder");
            searchPanel.add(exportBtn);

            // Add separator
            searchPanel.add(new javax.swing.JSeparator(javax.swing.SwingConstants.VERTICAL));

            searchPanel.add(new JLabel("Search:"));

            this.searchField = new JTextField(15);
            searchPanel.add(searchField);

            this.searchRegexCheckBox = new JCheckBox("Regex");
            searchPanel.add(searchRegexCheckBox);

            this.searchNextBtn = new JButton("Next");
            this.searchPrevBtn = new JButton("Prev");
            searchNextBtn.setEnabled(false);
            searchPrevBtn.setEnabled(false);
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

            // Setup event handlers
            setupSharedToolbarEventHandlers();

            return toolbar;
        }

        /**
         * Setup shared event handlers for toolbar components
         */
        protected void setupSharedToolbarEventHandlers() {
            // Export button
            exportBtn.addActionListener(e -> performExport());

            // Search field - update search results on text change
            javax.swing.Timer searchTimer = ThreadManager.createManagedTimer(300, e -> updateSearchResults());
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

            // Allow Enter key in search field to trigger next search
            searchField.addActionListener(e -> {
                if (!searchField.getText().trim().isEmpty() && !searchMatches.isEmpty()) {
                    navigateSearch(true);
                }
            });

            // Search navigation buttons
            searchNextBtn.addActionListener(e -> navigateSearch(true));
            searchPrevBtn.addActionListener(e -> navigateSearch(false));

            // Search regex checkbox
            searchRegexCheckBox.addActionListener(e -> updateSearchResults());

            // Filter field - trigger filter on text change with delay
            javax.swing.Timer filterTimer = ThreadManager.createManagedTimer(300, e -> applyFilter());
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

        /**
         * Shared search navigation logic
         */
        protected void navigateSearch(boolean next) {
            if (searchMatches.isEmpty()) {
                return; // No search results available
            }

            // Save current cursor position before navigation
            lastCursorPosition = getCursorPosition();

            if (next) {
                currentSearchIndex = (currentSearchIndex + 1) % searchMatches.size();
            } else {
                currentSearchIndex = (currentSearchIndex - 1 + searchMatches.size()) % searchMatches.size();
            }

            highlightCurrentMatch();
            updateSearchStatus((currentSearchIndex + 1) + " of " + searchMatches.size());
        }

        /**
         * Update search status display
         */
        protected void updateSearchStatus(String status) {
            searchStatusLabel.setText(status);
        }

        /**
         * Clear search state
         */
        protected void clearSearch() {
            searchMatches.clear();
            currentSearchIndex = -1;
            updateSearchStatus(" ");
            // Clear any highlighting in the searchable component
            clearSearchHighlighting();
            // Restore cursor position if we have one saved
            if (lastCursorPosition > 0) {
                setCursorPosition(lastCursorPosition);
            }
        }

        /**
         * Reset all filters and search
         */
        protected void resetAllFilters() {
            filterField.setText("");
            searchField.setText("");
            hideEmptyCheckBox.setSelected(false);
            clearSearch();
            applyFilter();
        }

        /**
         * Sanitize filename for cross-platform compatibility
         */
        protected String sanitizeFilename(String filename) {
            if (filename == null) return "unknown";
            return filename.replaceAll("[<>:\"/\\|?*()]", "_").replaceAll("\\s+", "_");
        }

        // ===== ENHANCED CONTEXT MENU UTILITIES =====

        /**
         * Copy text to system clipboard
         */
        protected void copyToClipboard(String text) {
            if (text == null || text.isEmpty()) {
                return;
            }
            try {
                java.awt.datatransfer.StringSelection stringSelection = new java.awt.datatransfer.StringSelection(text);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
            } catch (Exception e) {
                // Can't access api from static context, use System.err as fallback
                System.err.println("Failed to copy to clipboard: " + e.getMessage());
            }
        }

        /**
         * Get the line of text at a specific point in a JTextArea
         */
        protected String getLineAtPoint(JTextArea textArea, java.awt.Point point) {
            try {
                int position = textArea.viewToModel2D(point);
                int lineStart = textArea.getLineStartOffset(textArea.getLineOfOffset(position));
                int lineEnd = textArea.getLineEndOffset(textArea.getLineOfOffset(position));
                String lineText = textArea.getText(lineStart, lineEnd - lineStart);
                return lineText.replaceAll("\\r?\\n$", ""); // Remove trailing newline
            } catch (Exception e) {
                return "";
            }
        }

        /**
         * Extract quoted text at cursor position (text between " or ')
         */
        protected String getQuotedTextAtPoint(JTextArea textArea, java.awt.Point point) {
            try {
                int position = textArea.viewToModel2D(point);
                String text = textArea.getText();

                // Find the closest quote before and after the cursor
                int beforeQuote = -1;
                int afterQuote = -1;
                char quoteChar = '"';

                // Search backwards for opening quote
                for (int i = position - 1; i >= 0; i--) {
                    char c = text.charAt(i);
                    if (c == '"' || c == '\'') {
                        beforeQuote = i;
                        quoteChar = c;
                        break;
                    }
                }

                // Search forwards for closing quote (same type)
                if (beforeQuote != -1) {
                    for (int i = position; i < text.length(); i++) {
                        if (text.charAt(i) == quoteChar) {
                            afterQuote = i;
                            break;
                        }
                    }
                }

                // Extract text between quotes
                if (beforeQuote != -1 && afterQuote != -1 && afterQuote > beforeQuote + 1) {
                    return text.substring(beforeQuote + 1, afterQuote);
                }

                return null;
            } catch (Exception e) {
                return null;
            }
        }

        /**
         * Extract word at cursor position using regex [a-zA-Z0-9\.\-_]+
         */
        protected String getWordAtPoint(JTextArea textArea, java.awt.Point point) {
            try {
                int position = textArea.viewToModel2D(point);
                String text = textArea.getText();

                // Find word boundaries around cursor position
                int wordStart = position;
                int wordEnd = position;

                // Search backwards for word start
                while (wordStart > 0) {
                    char c = text.charAt(wordStart - 1);
                    if (!Character.isLetterOrDigit(c) && c != '.' && c != '-' && c != '_') {
                        break;
                    }
                    wordStart--;
                }

                // Search forwards for word end
                while (wordEnd < text.length()) {
                    char c = text.charAt(wordEnd);
                    if (!Character.isLetterOrDigit(c) && c != '.' && c != '-' && c != '_') {
                        break;
                    }
                    wordEnd++;
                }

                if (wordEnd > wordStart) {
                    String word = text.substring(wordStart, wordEnd);
                    return word.trim().isEmpty() ? null : word;
                }

                return null;
            } catch (Exception e) {
                return null;
            }
        }

        /**
         * Get preview text for menu items (first N characters)
         */
        protected String getPreviewText(String text, int maxLength) {
            if (text == null || text.isEmpty()) {
                return "";
            }
            if (text.length() <= maxLength) {
                return text;
            }
            return text.substring(0, maxLength) + "...";
        }

        /**
         * Create enhanced left panel context menu
         */
        protected JPopupMenu createLeftPanelContextMenu(String selectedItem, Runnable deleteAction, Runnable copyAllAction, Runnable exportAction) {
            JPopupMenu popup = new JPopupMenu();

            // Export item
            if (exportAction != null) {
                JMenuItem exportItem = new JMenuItem("Export");
                exportItem.addActionListener(e -> exportAction.run());
                popup.add(exportItem);
            }

            // Delete item
            if (deleteAction != null && selectedItem != null && !selectedItem.trim().isEmpty()) {
                JMenuItem deleteItem = new JMenuItem("Delete");
                deleteItem.addActionListener(e -> deleteAction.run());
                popup.add(deleteItem);
            }

            // Copy all to clipboard
            if (copyAllAction != null) {
                JMenuItem copyAllItem = new JMenuItem("Copy all to clipboard");
                copyAllItem.addActionListener(e -> copyAllAction.run());
                popup.add(copyAllItem);
            }

            return popup;
        }

        /**
         * Create enhanced right panel context menu
         */
        protected JPopupMenu createRightPanelContextMenu(JTextArea textArea, java.awt.Point clickPoint, Runnable exportAction) {
            JPopupMenu popup = new JPopupMenu();

            // Export item
            if (exportAction != null) {
                JMenuItem exportItem = new JMenuItem("Export");
                exportItem.addActionListener(e -> exportAction.run());
                popup.add(exportItem);
                popup.addSeparator();
            }

            // Copy all to clipboard
            JMenuItem copyAllItem = new JMenuItem("Copy all to clipboard");
            copyAllItem.addActionListener(e -> copyToClipboard(textArea.getText()));
            popup.add(copyAllItem);

            // Copy line to clipboard
            String lineText = getLineAtPoint(textArea, clickPoint);
            boolean lineNotEmpty = lineText != null && !lineText.trim().isEmpty();
            JMenuItem copyLineItem = new JMenuItem("Copy line to clipboard");
            copyLineItem.setEnabled(lineNotEmpty);
            if (lineNotEmpty) {
                copyLineItem.addActionListener(e -> copyToClipboard(lineText));
            }
            popup.add(copyLineItem);

            // Copy selected text to clipboard
            String selectedText = textArea.getSelectedText();
            boolean hasSelection = selectedText != null && !selectedText.isEmpty();
            JMenuItem copySelectedItem = new JMenuItem("Copy selected text to clipboard");
            copySelectedItem.setEnabled(hasSelection);
            if (hasSelection) {
                copySelectedItem.addActionListener(e -> copyToClipboard(selectedText));
            }
            popup.add(copySelectedItem);

            // Copy quoted text to clipboard
            String quotedText = getQuotedTextAtPoint(textArea, clickPoint);
            boolean hasQuotedText = quotedText != null && !quotedText.isEmpty();
            String quotedPreview = hasQuotedText ? getPreviewText(quotedText, 20) : "";
            JMenuItem copyQuotedItem = new JMenuItem("Copy quoted text to clipboard" +
                (hasQuotedText ? " (\"" + quotedPreview + "\")" : ""));
            copyQuotedItem.setEnabled(hasQuotedText);
            if (hasQuotedText) {
                copyQuotedItem.addActionListener(e -> copyToClipboard(quotedText));
            }
            popup.add(copyQuotedItem);

            // Copy word to clipboard
            String wordText = getWordAtPoint(textArea, clickPoint);
            boolean hasWord = wordText != null && !wordText.isEmpty();
            String wordPreview = hasWord ? getPreviewText(wordText, 20) : "";
            JMenuItem copyWordItem = new JMenuItem("Copy word to clipboard" +
                (hasWord ? " (" + wordPreview + ")" : ""));
            copyWordItem.setEnabled(hasWord);
            if (hasWord) {
                copyWordItem.addActionListener(e -> copyToClipboard(wordText));
            }
            popup.add(copyWordItem);

            return popup;
        }

        /**
         * Update search results when search text changes
         */
        protected void updateSearchResults() {
            String searchText = searchField.getText().trim();

            if (searchText.isEmpty()) {
                clearSearch();
                searchNextBtn.setEnabled(false);
                searchPrevBtn.setEnabled(false);
                return;
            }

            // Perform search and update matches
            performSearch();

            // Enable/disable navigation buttons based on results
            boolean hasMatches = !searchMatches.isEmpty();
            searchNextBtn.setEnabled(hasMatches);
            searchPrevBtn.setEnabled(hasMatches);

            if (hasMatches) {
                currentSearchIndex = 0;
                highlightCurrentMatch();
                updateSearchStatus("1 of " + searchMatches.size());
            } else {
                updateSearchStatus("No matches found");
            }
        }

        /**
         * Add word wrap toggle context menu to a JTextArea
         * Word wrap is enabled by default
         */
        protected void addWordWrapContextMenu(JTextArea textArea) {
            // Enable word wrap by default
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);

            // Create context menu
            JPopupMenu contextMenu = new JPopupMenu();
            JCheckBoxMenuItem wordWrapItem = new JCheckBoxMenuItem("Word Wrap", true);

            wordWrapItem.addActionListener(e -> {
                boolean wrap = wordWrapItem.isSelected();
                textArea.setLineWrap(wrap);
                textArea.setWrapStyleWord(wrap);
            });

            contextMenu.add(wordWrapItem);

            // Add mouse listener for right-click
            textArea.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showMenu(e);
                    }
                }

                private void showMenu(java.awt.event.MouseEvent e) {
                    contextMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            });
        }

        // Abstract methods that subclasses must implement
        protected abstract void performSearch();
        protected abstract void applyFilter();
        protected abstract void performExport();
        protected abstract void highlightCurrentMatch();
        protected abstract void clearSearchHighlighting();
        protected abstract int getCursorPosition();
        protected abstract void setCursorPosition(int position);
    }

    /**
     * Panel for displaying discovery results with categories menu and object list
     * Enhanced with search and filter functionality
     */
    public static class DiscoveryResultPanel extends BaseResultPanel {
        private final DiscoveryResult discoveryResult;
        private final JList<String> categoryList;
        private final JTextArea objectListArea;
        private final JSplitPane splitPane;
        private final MontoyaApi api;

        // Filter state (specific to DiscoveryResultPanel)
        private DefaultListModel<String> originalCategoryModel;
        private DefaultListModel<String> filteredCategoryModel;
        private String[] originalCategories;
        private boolean isFiltered = false;

        public DiscoveryResultPanel(DiscoveryResult discoveryResult, MontoyaApi api) {
            this.api = api;
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
            JPanel toolbar = createSharedToolbar();
            this.add(toolbar, BorderLayout.NORTH);
            
            // Create category list (left panel)
            this.categoryList = new JList<>(originalCategoryModel);
            categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            categoryList.setSelectedIndex(0); // Select first item by default
            
            // Create object list area (right panel)
            this.objectListArea = new JTextArea();
            objectListArea.setEditable(false);
            objectListArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

            // Add word wrap context menu (enabled by default)
            addWordWrapContextMenu(objectListArea);

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
        
        
        @Override
        protected void performSearch() {
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


        @Override
        protected void highlightCurrentMatch() {
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
        
        @Override
        protected void clearSearchHighlighting() {
            objectListArea.setSelectionStart(0);
            objectListArea.setSelectionEnd(0);
        }

        @Override
        protected void applyFilter() {
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

            // Select first item if available, or clear right panel if no items
            if (filteredCategoryModel.getSize() > 0) {
                categoryList.setSelectedIndex(0);
            } else {
                // Clear the right panel when no categories match the filter
                objectListArea.setText("");
                clearSearchHighlighting(); // Also clear any search highlighting
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
        
        @Override
        protected void resetAllFilters() {
            // Call parent reset logic
            super.resetAllFilters();

            // DiscoveryResultPanel specific reset logic
            categoryList.setModel(originalCategoryModel);
            isFiltered = false;

            // Select first item
            if (originalCategoryModel.getSize() > 0) {
                categoryList.setSelectedIndex(0);
            }

            updateObjectList();
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

        /**
         * Export filtered results to text files in a selected folder
         */
        @Override
        protected void performExport() {
            // Use filtered model to get currently visible categories
            DefaultListModel<String> modelToExport = filteredCategoryModel;

            if (modelToExport.isEmpty()) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "No categories to export. Please ensure there are items in the list.",
                        "Nothing to Export",
                        javax.swing.JOptionPane.INFORMATION_MESSAGE);
                });
                return;
            }

            // Show folder selection dialog
            javax.swing.JFileChooser folderChooser = new javax.swing.JFileChooser();
            folderChooser.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);
            folderChooser.setDialogTitle("Select Export Folder");

            int result = folderChooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
            if (result != javax.swing.JFileChooser.APPROVE_OPTION) {
                return; // User cancelled
            }

            java.io.File exportFolder = folderChooser.getSelectedFile();
            if (exportFolder == null || !exportFolder.exists() || !exportFolder.isDirectory()) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Invalid folder selected for export.",
                        "Export Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            // Perform export in background thread
            ThreadManager.createManagedRunAsync(() -> {
                try {
                    for (int i = 0; i < modelToExport.getSize(); i++) {
                        String categoryName = modelToExport.getElementAt(i);

                        // Get the objects for this category
                        java.util.Set<String> categoryObjects = new java.util.HashSet<>();
                        if (categoryName.contains("Default")) {
                            categoryObjects.addAll(discoveryResult.getDefaultObjects());
                        } else if (categoryName.contains("Custom")) {
                            categoryObjects.addAll(discoveryResult.getCustomObjects());
                        } else if (categoryName.contains("All")) {
                            categoryObjects.addAll(discoveryResult.getAllObjects());
                        }

                        if (!categoryObjects.isEmpty()) {
                            String safeFileName = sanitizeFilename(categoryName) + ".txt";
                            java.io.File outputFile = new java.io.File(exportFolder, safeFileName);

                            try (java.io.FileWriter writer = new java.io.FileWriter(outputFile)) {
                                writer.write("Category: " + categoryName + "\n");
                                writer.write("Exported at: " + java.time.LocalDateTime.now().toString() + "\n");
                                writer.write("Total objects: " + categoryObjects.size() + "\n");
                                writer.write("==========================================\n\n");

                                for (String objectName : categoryObjects) {
                                    writer.write(objectName + "\n");
                                }
                            }
                        }
                    }

                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Export completed successfully!\nFiles saved to: " + exportFolder.getAbsolutePath(),
                            "Export Successful",
                            javax.swing.JOptionPane.INFORMATION_MESSAGE);
                    });

                } catch (Exception e) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Error during export: " + e.getMessage(),
                            "Export Error",
                            javax.swing.JOptionPane.ERROR_MESSAGE);
                    });
                }
            });
        }

        /**
         * Sanitize filename for cross-platform compatibility
         */
        protected String sanitizeFilename(String filename) {
            if (filename == null) return "unknown";
            return filename.replaceAll("[<>:\"/\\|?*()]", "_").replaceAll("\\s+", "_");
        }

        @Override
        protected int getCursorPosition() {
            return objectListArea.getCaretPosition();
        }

        @Override
        protected void setCursorPosition(int position) {
            try {
                objectListArea.setCaretPosition(Math.min(position, objectListArea.getText().length()));
            } catch (IllegalArgumentException e) {
                objectListArea.setCaretPosition(0);
            }
        }
    }

    /**
     * Panel for displaying discovered routes with categories and route list
     * Similar structure to DiscoveryResultPanel but for navigation items and routes
     */
    public static class DiscoveredRoutesResultPanel extends BaseResultPanel {
        private RouteDiscoveryResult routeDiscoveryResult;
        private final JList<String> categoryList;
        private final JTextArea routeListArea;
        private final JSplitPane splitPane;
        private final MontoyaApi api;

        // Filter state
        private DefaultListModel<String> originalCategoryModel;
        private DefaultListModel<String> filteredCategoryModel;
        private boolean isFiltered = false;

        public DiscoveredRoutesResultPanel(RouteDiscoveryResult routeDiscoveryResult, MontoyaApi api) {
            this.api = api;
            this.routeDiscoveryResult = routeDiscoveryResult != null ? routeDiscoveryResult : new RouteDiscoveryResult();
            this.setLayout(new BorderLayout());

            // Initialize list models
            this.originalCategoryModel = new DefaultListModel<>();
            this.filteredCategoryModel = new DefaultListModel<>();

            // Populate with route categories (initially may be empty)
            updateCategoryModels();

            // Create category list
            this.categoryList = new JList<>(filteredCategoryModel);
            this.categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            this.categoryList.setVisibleRowCount(4);

            // Create route display area
            this.routeListArea = new JTextArea();
            this.routeListArea.setEditable(false);

            // Add word wrap context menu (enabled by default)
            addWordWrapContextMenu(routeListArea);

            // Create shared toolbar
            JPanel toolbarPanel = createSharedToolbar();
            this.add(toolbarPanel, BorderLayout.NORTH);

            // Create split pane
            JScrollPane categoryScrollPane = new JScrollPane(categoryList);
            categoryScrollPane.setPreferredSize(new Dimension(300, 0));
            JScrollPane routeScrollPane = new JScrollPane(routeListArea);

            this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, categoryScrollPane, routeScrollPane);
            this.splitPane.setDividerLocation(300);
            this.splitPane.setResizeWeight(0.3);

            this.add(splitPane, BorderLayout.CENTER);

            // Setup category selection listener
            categoryList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    updateRouteDisplay();
                }
            });

            // Initially display empty state
            updateRouteDisplay();

            // Add right-click context menu
            setupContextMenu();
        }

        /**
         * Update the panel with new route discovery results (for adding new discoveries)
         */
        public void updateRouteDiscoveryResult(RouteDiscoveryResult newResult) {
            if (newResult == null) return;

            // Merge new results with existing ones
            for (String categoryName : newResult.getCategoryNames()) {
                java.util.List<String> routes = newResult.getRoutesForCategory(categoryName);
                this.routeDiscoveryResult.addRouteCategory(categoryName, routes);
            }

            // Update UI models
            updateCategoryModels();

            // Select the newly added category
            String[] categoryNames = newResult.getCategoryNames().toArray(new String[0]);
            if (categoryNames.length > 0) {
                String newCategory = categoryNames[0]; // Select first new category
                for (int i = 0; i < filteredCategoryModel.getSize(); i++) {
                    if (filteredCategoryModel.get(i).equals(newCategory)) {
                        categoryList.setSelectedIndex(i);
                        break;
                    }
                }
            }
        }

        private void updateCategoryModels() {
            originalCategoryModel.clear();
            filteredCategoryModel.clear();

            for (String categoryName : routeDiscoveryResult.getCategoryNames()) {
                originalCategoryModel.addElement(categoryName);
                filteredCategoryModel.addElement(categoryName);
            }
        }

        private void updateRouteDisplay() {
            String selectedCategory = categoryList.getSelectedValue();
            if (selectedCategory == null) {
                if (routeDiscoveryResult.getCategoryNames().isEmpty()) {
                    routeListArea.setText("No route discovery results yet.\nClick 'Get Nav Items' to discover navigation routes.");
                } else {
                    routeListArea.setText("");
                }
                return;
            }

            java.util.List<String> routes = routeDiscoveryResult.getRoutesForCategory(selectedCategory);
            if (routes == null || routes.isEmpty()) {
                routeListArea.setText("No routes found in this category.");
                return;
            }

            // Display content URLs only, one per line
            StringBuilder content = new StringBuilder();
            for (String route : routes) {
                content.append(route).append("\n");
            }

            routeListArea.setText(content.toString());
            routeListArea.setCaretPosition(0);
        }

        private void setupContextMenu() {
            // Enhanced left panel context menu for category list
            categoryList.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showLeftPanelContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showLeftPanelContextMenu(e);
                    }
                }
            });

            // Enhanced right panel context menu for route text area
            routeListArea.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRightPanelContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRightPanelContextMenu(e);
                    }
                }
            });
        }

        private void showLeftPanelContextMenu(java.awt.event.MouseEvent e) {
            // Get selected category
            int index = categoryList.locationToIndex(e.getPoint());
            String selectedCategory = null;
            if (index >= 0) {
                categoryList.setSelectedIndex(index);
                selectedCategory = categoryList.getSelectedValue();
            }

            // Create enhanced context menu
            JPopupMenu popup = createLeftPanelContextMenu(
                selectedCategory,
                () -> deleteSelectedCategory(),
                () -> copyRightPanelToClipboard(),
                () -> performExport()
            );

            popup.show(categoryList, e.getX(), e.getY());
        }

        private void showRightPanelContextMenu(java.awt.event.MouseEvent e) {
            JPopupMenu popup = createRightPanelContextMenu(
                routeListArea,
                e.getPoint(),
                () -> performExport()
            );

            popup.show(routeListArea, e.getX(), e.getY());
        }

        private void deleteSelectedCategory() {
            String selectedCategory = categoryList.getSelectedValue();
            if (selectedCategory == null) {
                return;
            }

            // Confirm deletion
            int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete the category '" + selectedCategory + "'?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );

            if (result == JOptionPane.YES_OPTION) {
                // Remove from route discovery result
                routeDiscoveryResult.removeCategory(selectedCategory);

                // Update UI
                applyFilter();

                // Clear right panel if this was the selected category
                if (selectedCategory.equals(categoryList.getSelectedValue())) {
                    routeListArea.setText("");
                }
            }
        }

        private void copyRightPanelToClipboard() {
            String content = routeListArea.getText();
            if (content != null && !content.trim().isEmpty()) {
                copyToClipboard(content);
            }
        }


        private void exportRoutes() {
            // Show file chooser dialog first on EDT
            SwingUtilities.invokeLater(() -> {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setDialogTitle("Export Discovered Routes");

                String defaultFilename = "discovered-routes-" +
                    java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss")) + ".txt";
                fileChooser.setSelectedFile(new java.io.File(defaultFilename));

                int result = fileChooser.showSaveDialog(DiscoveredRoutesResultPanel.this);
                if (result != JFileChooser.APPROVE_OPTION) {
                    return; // User cancelled
                }

                java.io.File selectedFile = fileChooser.getSelectedFile();
                if (selectedFile == null) {
                    return;
                }

                // Ensure .txt extension
                if (!selectedFile.getName().toLowerCase().endsWith(".txt")) {
                    selectedFile = new java.io.File(selectedFile.getAbsolutePath() + ".txt");
                }

                final java.io.File finalFile = selectedFile;

                // Perform export in background thread
                new Thread(() -> {
                    try {
                        StringBuilder exportContent = new StringBuilder();

                        exportContent.append("Discovered Routes Export\n");
                        exportContent.append("Exported at: ").append(java.time.LocalDateTime.now()).append("\n\n");

                        int totalRoutes = routeDiscoveryResult.getTotalCount();
                        exportContent.append("Total routes: ").append(totalRoutes).append("\n\n");

                        for (String categoryName : routeDiscoveryResult.getCategoryNames()) {
                            exportContent.append("Category: ").append(categoryName).append("\n");
                            exportContent.append("=".repeat(categoryName.length() + 10)).append("\n");

                            java.util.List<String> routes = routeDiscoveryResult.getRoutesForCategory(categoryName);
                            for (String route : routes) {
                                exportContent.append(route).append("\n");
                            }
                            exportContent.append("\n");
                        }

                        // Write to selected file
                        try (java.io.FileWriter writer = new java.io.FileWriter(finalFile, java.nio.charset.StandardCharsets.UTF_8)) {
                            writer.write(exportContent.toString());
                        }

                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(
                                DiscoveredRoutesResultPanel.this,
                                "Routes exported to: " + finalFile.getAbsolutePath(),
                                "Export Complete",
                                JOptionPane.INFORMATION_MESSAGE
                            );
                        });

                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(
                                DiscoveredRoutesResultPanel.this,
                                "Failed to export routes: " + ex.getMessage(),
                                "Export Error",
                                JOptionPane.ERROR_MESSAGE
                            );
                        });
                    }
                }).start();
            });
        }

        @Override
        protected void performSearch() {
            String searchText = searchField.getText().trim();
            if (searchText.isEmpty()) {
                clearSearch();
                return;
            }

            String content = routeListArea.getText();
            if (content.isEmpty()) {
                return;
            }

            // Use the safe regex utility from ActionsTab
            try {
                java.util.regex.Pattern pattern = SafeRegex.safeCompile(
                    java.util.regex.Pattern.quote(searchText),
                    java.util.regex.Pattern.CASE_INSENSITIVE
                );
                java.util.List<Integer> matches = SafeRegex.safeFind(pattern, content);

                if (!matches.isEmpty()) {
                    searchMatches.clear();
                    searchMatches.addAll(matches);
                    currentSearchIndex = 0;
                    highlightCurrentMatch();
                    updateSearchStatus("1/" + matches.size());
                } else {
                    clearSearch();
                }
            } catch (Exception e) {
                clearSearch();
            }
        }

        @Override
        protected void applyFilter() {
            String filterText = filterField.getText().trim();

            if (filterText.isEmpty()) {
                // Clear filter
                categoryList.setModel(originalCategoryModel);
                isFiltered = false;
                return;
            }

            // Apply filter
            DefaultListModel<String> filtered = new DefaultListModel<>();
            for (int i = 0; i < originalCategoryModel.getSize(); i++) {
                String category = originalCategoryModel.getElementAt(i);
                if (category.toLowerCase().contains(filterText.toLowerCase())) {
                    filtered.addElement(category);
                }
            }

            categoryList.setModel(filtered);
            isFiltered = true;

            // Auto-select first item if available
            if (filtered.getSize() > 0) {
                categoryList.setSelectedIndex(0);
            } else {
                routeListArea.setText("No categories match the filter: " + filterText);
            }
        }

        @Override
        protected int getCursorPosition() {
            return routeListArea.getCaretPosition();
        }

        @Override
        protected void setCursorPosition(int position) {
            try {
                routeListArea.setCaretPosition(Math.min(position, routeListArea.getText().length()));
            } catch (IllegalArgumentException e) {
                routeListArea.setCaretPosition(0);
            }
        }

        @Override
        protected void performExport() {
            exportRoutes();
        }

        @Override
        protected void highlightCurrentMatch() {
            if (searchMatches.isEmpty() || currentSearchIndex < 0) return;

            int position = searchMatches.get(currentSearchIndex);
            routeListArea.setCaretPosition(position);
            routeListArea.requestFocus();
        }

        @Override
        protected void clearSearchHighlighting() {
            routeListArea.setSelectionStart(0);
            routeListArea.setSelectionEnd(0);
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
    public static class ObjectByNameResultPanel extends BaseResultPanel {
        private final ObjectByNameResult objectByNameResult;
        private final JList<String> objectList;
        private final JTextArea jsonDataArea;
        private final JSplitPane splitPane;
        private final List<BaseRequest> baseRequests;
        private final MontoyaApi api;

        // Additional field to hold current data for updates
        private java.util.Map<String, String> currentObjectData;

        // Filter state (specific to ObjectByNameResultPanel)
        private DefaultListModel<String> originalObjectModel;
        private DefaultListModel<String> filteredObjectModel;
        
        public ObjectByNameResultPanel(ObjectByNameResult objectByNameResult, List<BaseRequest> baseRequests, MontoyaApi api) {
            this.objectByNameResult = objectByNameResult;
            this.baseRequests = baseRequests;
            this.api = api;

            // Initialize current object data with initial data
            this.currentObjectData = new java.util.HashMap<>(objectByNameResult.getObjectEntries());
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
            JPanel toolbar = createSharedToolbar();
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

            // Add word wrap context menu (enabled by default)
            addWordWrapContextMenu(jsonDataArea);

            // Add selection listener to update JSON data
            objectList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    updateJsonData();
                    clearSearch(); // Clear search when changing selection
                }
            });

            // Right-click context menu will be added via SwingUtilities.invokeLater
            
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

            // Add mouse listener for right-click context menu
            javax.swing.SwingUtilities.invokeLater(() -> {
                addMouseListenerToObjectList();
            });
        }

        /**
         * Update the panel with new data without recreating the entire panel
         */
        public void updateWithNewData(ObjectByNameResult newObjectByNameResult) {
            // Store current filter state
            String currentFilterText = filterField.getText().trim();
            boolean hasActiveFilter = !currentFilterText.isEmpty() || hideEmptyCheckBox.isSelected();

            // Clear existing models
            originalObjectModel.clear();
            filteredObjectModel.clear();

            // Update current object data
            currentObjectData.clear();
            currentObjectData.putAll(newObjectByNameResult.getObjectEntries());

            // Populate with new object entries (add to original model only)
            for (String objectName : newObjectByNameResult.getObjectNames()) {
                originalObjectModel.addElement(objectName);
            }

            // Re-apply existing filter if there was one, otherwise show all items
            if (hasActiveFilter) {
                applyFilter(); // This will populate filteredObjectModel based on current filter criteria
            } else {
                // No filter was active, so copy all items to filtered model
                for (String objectName : newObjectByNameResult.getObjectNames()) {
                    filteredObjectModel.addElement(objectName);
                }
                objectList.setModel(originalObjectModel); // Use original model when no filter
            }

            // Reset selection
            if (originalObjectModel.getSize() > 0) {
                objectList.setSelectedIndex(0);
            }

            // Update JSON data
            updateJsonData();
        }

        /**
         * Add enhanced mouse listeners for context menus
         */
        private void addMouseListenerToObjectList() {
            setupEnhancedContextMenus();
        }

        private void setupEnhancedContextMenus() {
            // Enhanced left panel context menu for object list
            objectList.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    handleSelection(e);
                    if (e.isPopupTrigger()) {
                        showLeftPanelContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showLeftPanelContextMenu(e);
                    }
                }

                private void handleSelection(java.awt.event.MouseEvent e) {
                    int index = objectList.locationToIndex(e.getPoint());
                    if (index >= 0 && index < objectList.getModel().getSize()) {
                        objectList.setSelectedIndex(index);
                    }
                }
            });

            // Enhanced right panel context menu for JSON data area
            jsonDataArea.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRightPanelContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        showRightPanelContextMenu(e);
                    }
                }
            });
        }

        private void showLeftPanelContextMenu(java.awt.event.MouseEvent e) {
            // Get selected object
            int index = objectList.locationToIndex(e.getPoint());
            String selectedObject = null;
            if (index >= 0) {
                objectList.setSelectedIndex(index);
                selectedObject = objectList.getSelectedValue();
            }

            // Create enhanced context menu with original functionality preserved
            JPopupMenu popup = new JPopupMenu();

            // Export
            JMenuItem exportItem = new JMenuItem("Export");
            exportItem.addActionListener(action -> performExport());
            popup.add(exportItem);

            if (selectedObject != null) {
                popup.addSeparator();

                // Delete
                JMenuItem deleteItem = new JMenuItem("Delete");
                deleteItem.addActionListener(action -> deleteSelectedObject());
                popup.add(deleteItem);

                popup.addSeparator();

                // Original functionality
                JMenuItem showRequestItem = new JMenuItem("Show HTTP Request");
                showRequestItem.addActionListener(action -> showHttpRequest());
                popup.add(showRequestItem);

                JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
                sendToRepeaterItem.addActionListener(action -> sendSelectedToRepeater());
                popup.add(sendToRepeaterItem);

                JMenuItem copyRequestItem = new JMenuItem("Copy HTTP Request");
                copyRequestItem.addActionListener(action -> copyHttpRequestToClipboard());
                popup.add(copyRequestItem);

                popup.addSeparator();

                // Copy all to clipboard
                JMenuItem copyAllItem = new JMenuItem("Copy all to clipboard");
                copyAllItem.addActionListener(action -> copyRightPanelToClipboard());
                popup.add(copyAllItem);
            }

            popup.show(objectList, e.getX(), e.getY());
        }

        private void showRightPanelContextMenu(java.awt.event.MouseEvent e) {
            JPopupMenu popup = createRightPanelContextMenu(
                jsonDataArea,
                e.getPoint(),
                () -> performExport()
            );

            popup.show(jsonDataArea, e.getX(), e.getY());
        }

        private void deleteSelectedObject() {
            String selectedObject = objectList.getSelectedValue();
            if (selectedObject == null) {
                return;
            }

            // Confirm deletion
            int result = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete the object '" + selectedObject + "'?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            );

            if (result == JOptionPane.YES_OPTION) {
                // Remove from object result and current data
                objectByNameResult.removeObject(selectedObject);
                currentObjectData.remove(selectedObject);

                // Update UI
                applyFilter();

                // Clear right panel if this was the selected object
                if (selectedObject.equals(objectList.getSelectedValue())) {
                    jsonDataArea.setText("");
                }
            }
        }

        private void copyRightPanelToClipboard() {
            String content = jsonDataArea.getText();
            if (content != null && !content.trim().isEmpty()) {
                copyToClipboard(content);
            }
        }
        
        private void setupToolbarEventHandlers() {
            // Export button - export filtered results to files
            exportBtn.addActionListener(e -> performExport());

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
            javax.swing.Timer filterTimer = ThreadManager.createManagedTimer(300, e -> applyFilter());
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
                String jsonData = currentObjectData.get(selectedObject);
                jsonDataArea.setText(jsonData != null ? jsonData : "No data available");
                jsonDataArea.setCaretPosition(0); // Scroll to top
            } else {
                jsonDataArea.setText("Select an object to view its data");
            }
        }

        @Override
        protected void performSearch() {
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
        
        protected void navigateSearch(boolean forward) {
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
        
        protected void highlightCurrentMatch() {
            if (currentSearchIndex >= 0 && currentSearchIndex < searchMatches.size()) {
                int matchStart = searchMatches.get(currentSearchIndex);
                int matchEnd = matchStart + searchField.getText().length();
                
                jsonDataArea.setSelectionStart(matchStart);
                jsonDataArea.setSelectionEnd(matchEnd);
                jsonDataArea.requestFocus();
            }
        }
        
        protected void updateSearchStatus(String message) {
            searchStatusLabel.setText(message);
        }
        
        protected void applyFilter() {
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
        
        protected void clearSearch() {
            currentSearchIndex = -1;
            searchMatches.clear();
            lastSearchText = "";
            searchStatusLabel.setText(" ");
            jsonDataArea.setSelectionStart(0);
            jsonDataArea.setSelectionEnd(0);
        }

        protected void clearSearchHighlighting() {
            jsonDataArea.setSelectionStart(0);
            jsonDataArea.setSelectionEnd(0);
        }
        
        protected void resetAllFilters() {
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

        /**
         * Show the HTTP request for the currently selected object entry
         */
        private void showHttpRequest() {
            String selectedObject = objectList.getSelectedValue();
            if (selectedObject == null) {
                return;
            }

            // Extract request ID from object name format: "ObjectName Object (requestID-timestamp)"
            String requestId = extractRequestId(selectedObject);
            if (requestId == null) {
                api.logging().logToError("Could not extract request ID from object name: " + selectedObject);
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Could not extract request ID from object name",
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            BaseRequest matchingRequest = findBaseRequestById(requestId);
            if (matchingRequest == null) {
                return;
            }

            // Display the HTTP request in a new dialog
            displayHttpRequestDialog(matchingRequest, selectedObject);
        }

        /**
         * Send the currently selected object's request to Repeater directly
         */
        private void sendSelectedToRepeater() {
            String selectedObject = objectList.getSelectedValue();
            if (selectedObject == null) {
                return;
            }

            String requestId = extractRequestId(selectedObject);
            if (requestId == null) {
                api.logging().logToError("Could not extract request ID from object name: " + selectedObject);
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Could not extract request ID from object name",
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            BaseRequest matchingRequest = findBaseRequestById(requestId);
            if (matchingRequest == null) {
                return;
            }

            // Reconstruct the actual object retrieval request
            burp.api.montoya.http.message.requests.HttpRequest reconstructedRequest = reconstructObjectRetrievalRequest(matchingRequest, selectedObject);
            sendToRepeater(reconstructedRequest, matchingRequest.getId());
        }

        /**
         * Copy the currently selected object's HTTP request to clipboard
         */
        private void copyHttpRequestToClipboard() {
            String selectedObject = objectList.getSelectedValue();
            if (selectedObject == null) {
                return;
            }

            String requestId = extractRequestId(selectedObject);
            if (requestId == null) {
                api.logging().logToError("Could not extract request ID from object name: " + selectedObject);
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Could not extract request ID from object name",
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            BaseRequest matchingRequest = findBaseRequestById(requestId);
            if (matchingRequest == null) {
                return;
            }

            // Reconstruct the actual object retrieval request and format as proper HTTP request
            burp.api.montoya.http.message.requests.HttpRequest reconstructedRequest = reconstructObjectRetrievalRequest(matchingRequest, selectedObject);
            String requestText = formatAsHttpRequest(reconstructedRequest);

            // Copy to clipboard
            try {
                java.awt.datatransfer.StringSelection stringSelection = new java.awt.datatransfer.StringSelection(requestText);
                java.awt.datatransfer.Clipboard clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(stringSelection, null);

                api.logging().logToOutput("HTTP request copied to clipboard for: " + selectedObject);
            } catch (Exception e) {
                api.logging().logToError("Failed to copy request to clipboard: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Failed to copy request to clipboard: " + e.getMessage(),
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            }
        }

        /**
         * Extract request ID from object name format: "ObjectName Object (requestID-timestamp)"
         */
        private String extractRequestId(String objectName) {
            try {
                // Look for pattern "(requestX-" where X is the ID
                int startIndex = objectName.indexOf("(request");
                if (startIndex == -1) {
                    return null;
                }

                startIndex += "(request".length();
                int endIndex = objectName.indexOf("-", startIndex);
                if (endIndex == -1) {
                    return null;
                }

                return objectName.substring(startIndex, endIndex);
            } catch (Exception e) {
                api.logging().logToError("Error extracting request ID from: " + objectName + " - " + e.getMessage());
                return null;
            }
        }

        /**
         * Helper method to find BaseRequest by ID
         */
        private BaseRequest findBaseRequestById(String requestId) {
            try {
                int id = Integer.parseInt(requestId);
                for (BaseRequest request : baseRequests) {
                    if (request.getId() == id) {
                        return request;
                    }
                }
            } catch (NumberFormatException e) {
                api.logging().logToError("Invalid request ID format: " + requestId);
            }

            api.logging().logToError("Could not find BaseRequest with ID: " + requestId);
            javax.swing.SwingUtilities.invokeLater(() -> {
                javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                    "Could not find original request with ID: " + requestId,
                    "Error",
                    javax.swing.JOptionPane.ERROR_MESSAGE);
            });
            return null;
        }

        /**
         * Reconstruct the actual HTTP request that was sent to retrieve the specific object
         */
        private burp.api.montoya.http.message.requests.HttpRequest reconstructObjectRetrievalRequest(BaseRequest baseRequest, String objectName) {
            // Extract the actual object name from the object entry name
            // Format: "ObjectName Object (requestX-timestamp)" -> "ObjectName"
            String actualObjectName = objectName;
            if (objectName.contains(" Object (")) {
                actualObjectName = objectName.substring(0, objectName.indexOf(" Object ("));
            }

            api.logging().logToOutput("Reconstructing request for object: '" + actualObjectName + "' from entry: '" + objectName + "'");

            // Get the original HTTP request
            burp.api.montoya.http.message.requests.HttpRequest originalRequest = baseRequest.getRequestResponse().request();

            // Create the object retrieval payload using the same template as other operations
            // Need to escape the object name like in the bulk operations
            String escapedObjectName = actualObjectName.replace("\\", "\\\\").replace("\"", "\\\"");
            String objectRetrievalPayload = String.format(SPECIFIC_OBJECT_PAYLOAD_TEMPLATE, escapedObjectName);

            // Build new request with modified message parameter
            String newBody = "message=" + java.net.URLEncoder.encode(objectRetrievalPayload, java.nio.charset.StandardCharsets.UTF_8) + "&aura.context=" + extractAuraContext(originalRequest.bodyToString()) + "&aura.token=" + extractAuraToken(originalRequest.bodyToString());

            // Create the modified HTTP request
            return originalRequest.withBody(newBody);
        }

        /**
         * Extract aura.context from the original request body
         */
        private String extractAuraContext(String requestBody) {
            try {
                String[] params = requestBody.split("&");
                for (String param : params) {
                    if (param.startsWith("aura.context=")) {
                        return param.substring("aura.context=".length());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to extract aura.context: " + e.getMessage());
            }
            return "";
        }

        /**
         * Extract aura.token from the original request body
         */
        private String extractAuraToken(String requestBody) {
            try {
                String[] params = requestBody.split("&");
                for (String param : params) {
                    if (param.startsWith("aura.token=")) {
                        return param.substring("aura.token=".length());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to extract aura.token: " + e.getMessage());
            }
            return "";
        }

        /**
         * Format HTTP request as a proper HTTP request string
         */
        private String formatAsHttpRequest(burp.api.montoya.http.message.requests.HttpRequest httpRequest) {
            StringBuilder requestText = new StringBuilder();

            // Request line: METHOD path HTTP/1.1
            String url = httpRequest.url();
            String path = url.substring(url.indexOf('/', 8)); // Remove protocol and host
            requestText.append(httpRequest.method()).append(" ").append(path).append(" HTTP/1.1\r\n");

            // Headers
            for (burp.api.montoya.http.message.HttpHeader header : httpRequest.headers()) {
                requestText.append(header.name()).append(": ").append(header.value()).append("\r\n");
            }

            // Empty line between headers and body
            requestText.append("\r\n");

            // Body
            if (httpRequest.body().length() > 0) {
                requestText.append(httpRequest.bodyToString());
            }

            return requestText.toString();
        }

        /**
         * Display the HTTP request in a dialog window
         */
        private void displayHttpRequestDialog(BaseRequest baseRequest, String objectName) {
            javax.swing.JDialog dialog = new javax.swing.JDialog((java.awt.Frame) null, "HTTP Request for " + objectName, true);
            dialog.setDefaultCloseOperation(javax.swing.JDialog.DISPOSE_ON_CLOSE);
            dialog.setSize(800, 600);
            dialog.setLocationRelativeTo(this);

            // Create text area for HTTP request
            javax.swing.JTextArea requestArea = new javax.swing.JTextArea();
            requestArea.setEditable(false);
            requestArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));

            // Reconstruct the actual object retrieval request and format as proper HTTP request
            burp.api.montoya.http.message.requests.HttpRequest reconstructedRequest = reconstructObjectRetrievalRequest(baseRequest, objectName);
            String formattedRequest = formatAsHttpRequest(reconstructedRequest);

            requestArea.setText(formattedRequest);
            requestArea.setCaretPosition(0);

            // Add scroll pane
            javax.swing.JScrollPane scrollPane = new javax.swing.JScrollPane(requestArea);

            // Add buttons panel
            javax.swing.JPanel buttonPanel = new javax.swing.JPanel(new java.awt.FlowLayout());

            javax.swing.JButton sendToRepeaterBtn = new javax.swing.JButton("Send to Repeater");
            sendToRepeaterBtn.addActionListener(e -> {
                sendToRepeater(reconstructedRequest, baseRequest.getId());
                dialog.dispose();
            });

            javax.swing.JButton closeBtn = new javax.swing.JButton("Close");
            closeBtn.addActionListener(e -> dialog.dispose());

            buttonPanel.add(sendToRepeaterBtn);
            buttonPanel.add(closeBtn);

            dialog.setLayout(new java.awt.BorderLayout());
            dialog.add(scrollPane, java.awt.BorderLayout.CENTER);
            dialog.add(buttonPanel, java.awt.BorderLayout.SOUTH);

            dialog.setVisible(true);
        }

        /**
         * Send the HTTP request to Burp's Repeater tool
         */
        private void sendToRepeater(burp.api.montoya.http.message.requests.HttpRequest httpRequest, int requestId) {
            try {
                // Send to repeater
                api.repeater().sendToRepeater(httpRequest, "Auraditor - " + requestId);

                api.logging().logToOutput("Sent request " + requestId + " to Repeater");

            } catch (Exception e) {
                api.logging().logToError("Failed to send request to Repeater: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Failed to send request to Repeater: " + e.getMessage(),
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            }
        }

        /**
         * Export filtered results to text files in a selected folder
         */
        protected void performExport() {
            // Use filtered model to get currently visible items
            DefaultListModel<String> modelToExport = filteredObjectModel;

            if (modelToExport.isEmpty()) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "No objects to export. Please ensure there are items in the list.",
                        "Nothing to Export",
                        javax.swing.JOptionPane.INFORMATION_MESSAGE);
                });
                return;
            }

            // Show folder selection dialog
            javax.swing.JFileChooser folderChooser = new javax.swing.JFileChooser();
            folderChooser.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);
            folderChooser.setDialogTitle("Select Export Folder");

            int result = folderChooser.showSaveDialog(api.userInterface().swingUtils().suiteFrame());
            if (result != javax.swing.JFileChooser.APPROVE_OPTION) {
                return; // User cancelled
            }

            java.io.File exportFolder = folderChooser.getSelectedFile();
            if (exportFolder == null || !exportFolder.exists() || !exportFolder.isDirectory()) {
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Invalid folder selected for export.",
                        "Export Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
                return;
            }

            // Perform export in background thread
            ThreadManager.createManagedRunAsync(() -> {
                try {
                    int exportedCount = 0;
                    String timestamp = java.time.LocalDateTime.now().format(
                        java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

                    for (int i = 0; i < modelToExport.getSize(); i++) {
                        String objectName = modelToExport.getElementAt(i);
                        String jsonData = currentObjectData.get(objectName);

                        if (jsonData != null && !jsonData.trim().isEmpty()) {
                            // Create safe filename
                            String safeFilename = sanitizeFilename(objectName) + "_" + timestamp + ".txt";
                            java.io.File outputFile = new java.io.File(exportFolder, safeFilename);

                            // Write content to file
                            try (java.io.FileWriter writer = new java.io.FileWriter(outputFile, java.nio.charset.StandardCharsets.UTF_8)) {
                                writer.write("Object Name: " + objectName + "\n");
                                writer.write("Export Time: " + java.time.LocalDateTime.now().toString() + "\n");
                                writer.write("=" + "=".repeat(60) + "\n\n");
                                writer.write(jsonData);
                                exportedCount++;
                            }
                        }
                    }

                    final int finalExportedCount = exportedCount;
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Successfully exported " + finalExportedCount + " objects to:\n" + exportFolder.getAbsolutePath(),
                            "Export Complete",
                            javax.swing.JOptionPane.INFORMATION_MESSAGE);
                    });

                    api.logging().logToOutput("Exported " + finalExportedCount + " objects to: " + exportFolder.getAbsolutePath());

                } catch (Exception e) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Failed to export objects: " + e.getMessage(),
                            "Export Error",
                            javax.swing.JOptionPane.ERROR_MESSAGE);
                    });
                    api.logging().logToError("Export failed: " + e.getMessage());
                }
            });
        }

        /**
         * Sanitize filename for cross-platform compatibility
         */
        protected String sanitizeFilename(String filename) {
            if (filename == null || filename.trim().isEmpty()) {
                return "unnamed_object";
            }

            // Remove/replace problematic characters
            String sanitized = filename
                .replaceAll("[<>:\"/\\\\|?*]", "_")  // Replace invalid characters
                .replaceAll("\\s+", "_")              // Replace whitespace with underscore
                .replaceAll("_{2,}", "_");            // Replace multiple underscores with single

            // Limit length (Windows has 255 char limit, but we'll be conservative)
            if (sanitized.length() > 100) {
                sanitized = sanitized.substring(0, 100);
            }

            // Ensure it doesn't start/end with dots or spaces
            sanitized = sanitized.replaceAll("^[.\\s]+|[.\\s]+$", "");

            // If empty after sanitization, provide default
            if (sanitized.isEmpty()) {
                sanitized = "unnamed_object";
            }

            return sanitized;
        }

        @Override
        protected int getCursorPosition() {
            return jsonDataArea.getCaretPosition();
        }

        @Override
        protected void setCursorPosition(int position) {
            try {
                jsonDataArea.setCaretPosition(Math.min(position, jsonDataArea.getText().length()));
            } catch (IllegalArgumentException e) {
                jsonDataArea.setCaretPosition(0);
            }
        }

    }

    /**
     * Panel for displaying retrieved records results with two-pane layout
     */
    public static class RetrievedRecordsResultPanel extends BaseResultPanel {
        private final String recordId;
        private final String recordData;
        private final JSplitPane splitPane;
        private final JList<String> recordList;
        private final JTextArea dataArea;
        private final BaseRequest baseRequest;
        private final MontoyaApi api;

        public RetrievedRecordsResultPanel(String recordId, String recordData, BaseRequest baseRequest, MontoyaApi api) {
            this.recordId = recordId;
            this.recordData = recordData;
            this.baseRequest = baseRequest;
            this.api = api;
            this.setLayout(new BorderLayout());

            // Create shared toolbar
            add(createSharedToolbar(), BorderLayout.NORTH);

            // Create record list
            DefaultListModel<String> listModel = new DefaultListModel<>();
            listModel.addElement(recordId);
            this.recordList = new JList<>(listModel);
            recordList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            recordList.setSelectedIndex(0);

            // Create data area
            this.dataArea = new JTextArea(recordData);
            dataArea.setEditable(false);
            dataArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

            // Add word wrap context menu (enabled by default)
            addWordWrapContextMenu(dataArea);

            // Create split pane
            JScrollPane recordScrollPane = new JScrollPane(recordList);
            JScrollPane dataScrollPane = new JScrollPane(dataArea);
            recordScrollPane.setPreferredSize(new Dimension(200, 400));
            dataScrollPane.setPreferredSize(new Dimension(600, 400));

            this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, recordScrollPane, dataScrollPane);
            splitPane.setDividerLocation(200);
            splitPane.setResizeWeight(0.25);

            add(splitPane, BorderLayout.CENTER);

            // Add selection listener
            recordList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    String selectedRecord = recordList.getSelectedValue();
                    if (selectedRecord != null) {
                        dataArea.setText(recordData);
                    }
                }
            });

            // Add right-click context menu
            addMouseListenerToRecordList();
        }

        /**
         * Add mouse listener to record list for right-click context menu
         */
        private void addMouseListenerToRecordList() {
            // Remove ALL existing mouse listeners to prevent interference
            java.awt.event.MouseListener[] existingListeners = recordList.getMouseListeners();
            for (java.awt.event.MouseListener listener : existingListeners) {
                recordList.removeMouseListener(listener);
            }

            // Add a single mouse listener that handles popup properly
            java.awt.event.MouseAdapter mouseAdapter = new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    // Handle selection on any click
                    handleSelection(e);
                    // Only show popup on popup trigger
                    if (e.isPopupTrigger()) {
                        showContextMenu(e);
                    }
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    // Only show popup on popup trigger (for Mac compatibility)
                    if (e.isPopupTrigger()) {
                        showContextMenu(e);
                    }
                }

                private void handleSelection(java.awt.event.MouseEvent e) {
                    int index = recordList.locationToIndex(e.getPoint());
                    if (index >= 0 && index < recordList.getModel().getSize()) {
                        recordList.setSelectedIndex(index);
                    }
                }

                private void showContextMenu(java.awt.event.MouseEvent e) {
                    int index = recordList.locationToIndex(e.getPoint());

                    if (index >= 0 && index < recordList.getModel().getSize()) {
                        // Ensure item is selected (may already be selected from handleSelection)
                        if (recordList.getSelectedIndex() != index) {
                            recordList.setSelectedIndex(index);
                        }
                        String selectedValue = recordList.getSelectedValue();

                        javax.swing.JPopupMenu popup = new javax.swing.JPopupMenu();

                        // Only show context menu items if we have baseRequest information
                        if (baseRequest != null) {
                            javax.swing.JMenuItem showRequestItem = new javax.swing.JMenuItem("Show HTTP Request");
                            showRequestItem.addActionListener(action -> showHttpRequest());
                            popup.add(showRequestItem);

                            javax.swing.JMenuItem sendToRepeaterItem = new javax.swing.JMenuItem("Send to Repeater");
                            sendToRepeaterItem.addActionListener(action -> sendSelectedToRepeater());
                            popup.add(sendToRepeaterItem);

                            javax.swing.JMenuItem copyRequestItem = new javax.swing.JMenuItem("Copy HTTP Request");
                            copyRequestItem.addActionListener(action -> copyHttpRequestToClipboard());
                            popup.add(copyRequestItem);
                        } else {
                            // Show informational message when baseRequest is not available
                            javax.swing.JMenuItem noRequestItem = new javax.swing.JMenuItem("No request information available");
                            noRequestItem.setEnabled(false);
                            popup.add(noRequestItem);
                        }

                        popup.show(recordList, e.getX(), e.getY());
                    }
                }
            };

            recordList.addMouseListener(mouseAdapter);
        }

        @Override
        protected void performSearch() {
            // Simple search implementation
            String searchText = searchField.getText().trim();
            if (searchText.isEmpty()) {
                clearSearchHighlighting();
                return;
            }

            String text = dataArea.getText();
            searchMatches.clear();
            currentSearchIndex = -1;
            lastSearchText = searchText;

            int index = text.indexOf(searchText);
            while (index >= 0) {
                searchMatches.add(index);
                index = text.indexOf(searchText, index + 1);
            }

            if (!searchMatches.isEmpty()) {
                currentSearchIndex = 0;
                highlightCurrentMatch();
                updateSearchStatus("1 of " + searchMatches.size());
            } else {
                updateSearchStatus("No matches found");
            }
        }

        @Override
        protected void applyFilter() {
            // Simple filter implementation - no filtering for records panel
        }

        @Override
        protected void performExport() {
            // Export implementation
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            fileChooser.setDialogTitle("Select folder to export record data");

            if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                File selectedFolder = fileChooser.getSelectedFile();
                String filename = sanitizeFilename(recordId) + ".txt";
                File outputFile = new File(selectedFolder, filename);

                try (java.io.FileWriter writer = new java.io.FileWriter(outputFile)) {
                    writer.write("Record ID: " + recordId + "\n\n");
                    writer.write(recordData);
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Record exported successfully to:\n" + outputFile.getAbsolutePath(),
                            "Export Complete",
                            javax.swing.JOptionPane.INFORMATION_MESSAGE);
                    });
                } catch (Exception e) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                            "Export failed: " + e.getMessage(),
                            "Export Error",
                            javax.swing.JOptionPane.ERROR_MESSAGE);
                    });
                }
            }
        }

        @Override
        protected void highlightCurrentMatch() {
            if (currentSearchIndex >= 0 && currentSearchIndex < searchMatches.size()) {
                int matchStart = searchMatches.get(currentSearchIndex);
                int matchEnd = matchStart + searchField.getText().length();
                dataArea.setSelectionStart(matchStart);
                dataArea.setSelectionEnd(matchEnd);
                dataArea.requestFocus();
            }
        }

        @Override
        protected void clearSearchHighlighting() {
            dataArea.setSelectionStart(0);
            dataArea.setSelectionEnd(0);
        }

        /**
         * Add a new record to the panel
         */
        public void addRecord(String recordId, String recordData) {
            DefaultListModel<String> model = (DefaultListModel<String>) recordList.getModel();
            model.addElement(recordId);
            recordList.setSelectedIndex(model.getSize() - 1);
            dataArea.setText(recordData);
        }

        /**
         * Show HTTP request dialog for the selected record
         */
        private void showHttpRequest() {
            String selectedRecord = recordList.getSelectedValue();
            if (selectedRecord == null || baseRequest == null) {
                return;
            }

            // Create the record retrieval request
            HttpRequest recordRequest = reconstructRecordRetrievalRequest(baseRequest, selectedRecord);
            displayHttpRequestDialog(baseRequest, "Record: " + selectedRecord, recordRequest);
        }

        /**
         * Send selected record request to Repeater
         */
        private void sendSelectedToRepeater() {
            String selectedRecord = recordList.getSelectedValue();
            if (selectedRecord == null || baseRequest == null) {
                return;
            }

            // Create the record retrieval request
            HttpRequest recordRequest = reconstructRecordRetrievalRequest(baseRequest, selectedRecord);
            sendToRepeater(recordRequest, baseRequest.getId());
        }

        /**
         * Copy selected record request to clipboard
         */
        private void copyHttpRequestToClipboard() {
            String selectedRecord = recordList.getSelectedValue();
            if (selectedRecord == null || baseRequest == null) {
                return;
            }

            // Create the record retrieval request
            HttpRequest recordRequest = reconstructRecordRetrievalRequest(baseRequest, selectedRecord);
            String requestText = formatAsHttpRequest(recordRequest);

            // Copy to clipboard
            try {
                java.awt.datatransfer.StringSelection stringSelection = new java.awt.datatransfer.StringSelection(requestText);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);

                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "HTTP request copied to clipboard",
                        "Copy Successful",
                        javax.swing.JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                api.logging().logToError("Failed to copy to clipboard: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Failed to copy to clipboard: " + e.getMessage(),
                        "Copy Failed",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            }
        }

        /**
         * Reconstruct the HTTP request used to retrieve the record
         */
        private HttpRequest reconstructRecordRetrievalRequest(BaseRequest baseRequest, String recordId) {
            // Escape the record ID for JSON
            String escapedRecordId = recordId.replace("\\", "\\\\").replace("\"", "\\\"");

            // Create the record retrieval payload with the specified format
            String recordPayload = String.format(
                "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"recordId\":\"%s\",\"record\":null,\"inContextOfComponent\":\"\",\"mode\":\"VIEW\",\"layoutType\":\"FULL\",\"defaultFieldValues\":null,\"navigationLocation\":\"LIST_VIEW_ROW\"}}]}",
                escapedRecordId
            );

            // Get the original HTTP request
            HttpRequest originalRequest = baseRequest.getRequestResponse().request();

            // Build new request with modified message parameter
            String newBody = "message=" + java.net.URLEncoder.encode(recordPayload, java.nio.charset.StandardCharsets.UTF_8) +
                           "&aura.context=" + extractAuraContext(originalRequest.bodyToString()) +
                           "&aura.token=" + extractAuraToken(originalRequest.bodyToString());

            // Create the modified HTTP request
            return originalRequest.withBody(newBody);
        }

        /**
         * Extract aura.context from the original request body
         */
        private String extractAuraContext(String requestBody) {
            try {
                String[] parts = requestBody.split("&");
                for (String part : parts) {
                    if (part.startsWith("aura.context=")) {
                        return part.substring("aura.context=".length());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to extract aura.context: " + e.getMessage());
            }
            return "";
        }

        /**
         * Extract aura.token from the original request body
         */
        private String extractAuraToken(String requestBody) {
            try {
                String[] parts = requestBody.split("&");
                for (String part : parts) {
                    if (part.startsWith("aura.token=")) {
                        return part.substring("aura.token=".length());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Failed to extract aura.token: " + e.getMessage());
            }
            return "";
        }

        /**
         * Display HTTP request in a dialog similar to ObjectByNameResultPanel
         */
        private void displayHttpRequestDialog(BaseRequest baseRequest, String title, HttpRequest request) {
            javax.swing.SwingUtilities.invokeLater(() -> {
                javax.swing.JDialog dialog = new javax.swing.JDialog();
                dialog.setTitle("HTTP Request - " + title);
                dialog.setModal(true);
                dialog.setSize(800, 600);
                dialog.setLocationRelativeTo(this);

                javax.swing.JTextArea textArea = new javax.swing.JTextArea();
                textArea.setEditable(false);
                textArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
                textArea.setText(formatAsHttpRequest(request));

                javax.swing.JScrollPane scrollPane = new javax.swing.JScrollPane(textArea);
                dialog.add(scrollPane);

                dialog.setVisible(true);
            });
        }

        /**
         * Send request to Repeater similar to ObjectByNameResultPanel
         */
        private void sendToRepeater(HttpRequest httpRequest, int requestId) {
            try {
                api.repeater().sendToRepeater(httpRequest, "Record Request " + requestId);
                api.logging().logToOutput("Sent record request " + requestId + " to Repeater");
            } catch (Exception e) {
                api.logging().logToError("Failed to send to Repeater: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() -> {
                    javax.swing.JOptionPane.showMessageDialog(api.userInterface().swingUtils().suiteFrame(),
                        "Failed to send to Repeater: " + e.getMessage(),
                        "Error",
                        javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            }
        }

        /**
         * Format HTTP request as text similar to ObjectByNameResultPanel
         */
        private String formatAsHttpRequest(HttpRequest request) {
            StringBuilder sb = new StringBuilder();

            // Request line
            sb.append(request.method()).append(" ").append(request.path());
            if (request.query() != null && !request.query().isEmpty()) {
                sb.append("?").append(request.query());
            }
            sb.append(" HTTP/1.1\n");

            // Headers
            for (burp.api.montoya.http.message.HttpHeader header : request.headers()) {
                sb.append(header.name()).append(": ").append(header.value()).append("\n");
            }

            // Empty line before body
            sb.append("\n");

            // Body
            if (request.body().length() > 0) {
                sb.append(request.bodyToString());
            }

            return sb.toString();
        }

        @Override
        protected int getCursorPosition() {
            return dataArea.getCaretPosition();
        }

        @Override
        protected void setCursorPosition(int position) {
            try {
                dataArea.setCaretPosition(Math.min(position, dataArea.getText().length()));
            } catch (IllegalArgumentException e) {
                dataArea.setCaretPosition(0);
            }
        }
    }

    /**
     * Check if the tab is currently processing an operation
     */
    public boolean isProcessing() {
        return currentOperationThread != null && currentOperationThread.isAlive();
    }

    /**
     * Reset discovery state (used when deleting discovery tabs)
     */
    public void resetDiscoveryState() {
        discoveredDefaultObjects.clear();
        discoveredCustomObjects.clear();
        availableDiscoveryResults.clear();
        discoveryResultSelector.removeAllItems();
        discoveryResultSelector.setEnabled(false);

        // Reset UI states
        findDefaultObjectsBtn.setEnabled(false);
        findCustomObjectsBtn.setEnabled(false);
        findAllObjectsBtn.setEnabled(false);

        api.logging().logToOutput("Discovery state has been reset");
    }

    /**
     * Reset the route discovery state
     */
    public void resetRouteDiscoveryState() {
        routeDiscoveryResultCounter = 0;

        // Reset UI state
        getNavItemsBtn.setEnabled(false);

        api.logging().logToOutput("Route discovery state has been reset");
    }

    /**
     * Cancel any running operation
     */
    public void cancelOperation() {
        api.logging().logToOutput("Operation cancelled - stopping all requests");
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
    }

    /**
     * Cleanup method to properly dispose of resources when extension is unloaded
     */
    public void cleanup() {
        try {
            // Cancel any running operation
            cancelOperation();

            api.logging().logToOutput("ActionsTab cleanup completed");
        } catch (Exception e) {
            api.logging().logToError("Error during ActionsTab cleanup: " + e.getMessage());
        }
    }

    /**
     * Perform all three sitemap searches at once to avoid multiple sitemap iterations
     */
    private void performAllSitemapSearches(BaseRequest baseRequest, boolean sitemapOnly) {
        api.logging().logToOutput("Starting consolidated sitemap parsing for all search types (sitemap only: " + sitemapOnly + ")...");

        try {
            // Reset cancellation flags and discovered items for all searches
            routerPathsCancelled = false;
            jsPathsCancelled = false;
            descriptorsCancelled = false;
            discoveredRouterPaths.clear();
            discoveredJSPaths.clear();
            discoveredDescriptors.clear();

            // Generate result IDs for each search type
            String routerPathsResultId = generateRouteDiscoveryResultIdWithReuseCheck();
            String jsPathsResultId = generateRouteDiscoveryResultIdWithReuseCheck();
            String descriptorsResultId = generateRouteDiscoveryResultIdWithReuseCheck();

            // Initialize results objects for all searches
            currentRouterPathsResults = new RouteDiscoveryResult();
            currentJSPathsResults = new RouteDiscoveryResult();
            currentDescriptorResults = new RouteDiscoveryResult();

            // Process sitemap with all three processors at once
            processSitemapWithMultipleProcessors(baseRequest, sitemapOnly, routerPathsResultId, jsPathsResultId, descriptorsResultId);

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Error during consolidated sitemap searches: " + e.getMessage());
                api.logging().logToError("Consolidated sitemap searches failed: " + e.getMessage());
            });
        }
    }

    /**
     * Process sitemap once with multiple processors to avoid multiple iterations
     */
    private void processSitemapWithMultipleProcessors(BaseRequest baseRequest, boolean sitemapOnly, String routerPathsResultId, String jsPathsResultId, String descriptorsResultId) {

        try {
            // Get sitemap items once
            api.logging().logToOutput("Retrieving sitemap entries for all searches...");
            List<HttpRequestResponse> sitemapItems = new ArrayList<>();
            sitemapItems.addAll(api.siteMap().requestResponses());

            api.logging().logToOutput("Total sitemap items retrieved: " + sitemapItems.size());

            // Filter for JavaScript responses once
            List<HttpRequestResponse> jsResponses = new ArrayList<>();
            for (HttpRequestResponse item : sitemapItems) {
                // Check for cancellation from any search
                if (routerPathsCancelled || jsPathsCancelled || descriptorsCancelled ||
                    operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Consolidated sitemap searches cancelled by user");
                    return;
                }

                try {
                    if (item.response() != null && item.response().mimeType() == MimeType.SCRIPT) {
                        // Apply scope filtering if sitemapOnly is false
                        if (!sitemapOnly || api.scope().isInScope(item.request().url())) {
                            jsResponses.add(item);
                        }
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error filtering JavaScript response: " + e.getMessage());
                }
            }

            api.logging().logToOutput("JavaScript responses found: " + jsResponses.size());

            // Process each JavaScript response with all three processors
            AtomicInteger processedItems = new AtomicInteger(0);
            int totalItems = jsResponses.size();

            // Generate timestamp for JS paths processing (required by that method)
            String jsTimestamp = generateTimestamp();

            for (HttpRequestResponse jsResponse : jsResponses) {
                // Check for cancellation from any search
                if (routerPathsCancelled || jsPathsCancelled || descriptorsCancelled ||
                    operationCancelled || Thread.currentThread().isInterrupted()) {
                    api.logging().logToOutput("Consolidated sitemap searches cancelled by user");
                    return;
                }

                try {
                    // Process with router paths processor
                    if (!routerPathsCancelled) {
                        processJavaScriptResponseForRouterPaths(jsResponse, "consolidated", jsTimestamp);
                    }

                    // Process with JS paths processor
                    if (!jsPathsCancelled) {
                        processJavaScriptResponseForPaths(jsResponse, baseRequest, jsTimestamp);
                    }

                    // Process with descriptors processor
                    if (!descriptorsCancelled) {
                        processJavaScriptResponseForDescriptors(jsResponse, jsTimestamp);
                    }

                    // Update progress
                    int processed = processedItems.incrementAndGet();
                    int progress = (processed * 100) / totalItems;

                    // Update status for all searches
                    SwingUtilities.invokeLater(() -> {
                        performAllSitemapSearchesBtn.setText("⟳ All Searches (" + progress + "%)");
                    });

                    if (processed % 10 == 0) {
                        api.logging().logToOutput("Processed " + processed + "/" + totalItems +
                            " JavaScript files for all searches (" + progress + "%)");
                    }

                } catch (Exception e) {
                    api.logging().logToError("Error processing JavaScript response in consolidated search: " + e.getMessage());
                }
            }

            // Completion - finalize all results and create tabs
            SwingUtilities.invokeLater(() -> {
                // Generate session timestamp for this consolidated operation
                String sessionTimestamp = java.time.LocalDateTime.now().format(
                    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

                int routerPathsFound = discoveredRouterPaths.size();
                int jsPathsFound = discoveredJSPaths.size();
                int descriptorsFound = discoveredDescriptors.size();
                int totalFound = routerPathsFound + jsPathsFound + descriptorsFound;

                // Finalize router paths results
                if (routerPathsFound > 0 && currentRouterPathsResults != null) {
                    finalizeRouterPathsResults(routerPathsResultId, sessionTimestamp);
                }

                // Finalize JS paths results
                if (jsPathsFound > 0 && currentJSPathsResults != null && resultTabCallback != null) {
                    if (shouldReuseTab()) {
                        resultTabCallback.updateDiscoveredRoutesTab(jsPathsResultId, currentJSPathsResults);
                    } else {
                        resultTabCallback.createDiscoveredRoutesTab(jsPathsResultId, currentJSPathsResults);
                    }
                }

                // Finalize descriptors results
                if (descriptorsFound > 0 && currentDescriptorResults != null && resultTabCallback != null) {
                    if (shouldReuseTab()) {
                        resultTabCallback.updateDiscoveredRoutesTab(descriptorsResultId, currentDescriptorResults);
                    } else {
                        resultTabCallback.createDiscoveredRoutesTab(descriptorsResultId, currentDescriptorResults);
                    }
                }

                clearBusyState();

                showStatusMessage("✓ All sitemap searches completed: " +
                    routerPathsFound + " router paths, " +
                    jsPathsFound + " JS paths, " +
                    descriptorsFound + " descriptors found",
                    totalFound > 0 ? Color.GREEN : Color.ORANGE);

                api.logging().logToOutput("All sitemap searches completed successfully:");
                api.logging().logToOutput("  JavaScript responses analyzed: " + totalItems);
                api.logging().logToOutput("  Router paths found: " + routerPathsFound);
                api.logging().logToOutput("  JS paths found: " + jsPathsFound);
                api.logging().logToOutput("  Descriptors found: " + descriptorsFound);
            });

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                clearBusyState();
                showErrorMessage("Error during consolidated sitemap processing: " + e.getMessage());
                api.logging().logToError("Consolidated sitemap processing failed: " + e.getMessage());
            });
        }
    }

}