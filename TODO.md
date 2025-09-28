# Auraditor TODO List - Future Enhancements

This document contains detailed specifications for future improvements to the Auraditor Burp Suite extension. Each item includes implementation details, technical requirements, and integration points to enable AI-assisted development.

## Priority 1: UI/UX Improvements

### 1. Add Scrollbar to Actions Page
**Description:** Add vertical scrollbar to the main actions panel to handle cases where screen height is insufficient to display all buttons.

**Implementation Details:**
- **File:** `src/main/java/auraditor/suite/ui/ActionsTab.java`
- **Location:** Line ~554 where `actionsPanel` is created
- **Action Required:** Wrap the `actionsPanel` in a `JScrollPane`
- **Current Code:** `JPanel actionsPanel = new JPanel(new GridBagLayout());`
- **Suggested Fix:**
  ```java
  JPanel actionsPanel = new JPanel(new GridBagLayout());
  JScrollPane scrollPane = new JScrollPane(actionsPanel);
  scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
  scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
  // Add scrollPane to mainPanel instead of actionsPanel
  ```

### 2. Add Pagination Controls UI
**Description:** Add user interface controls for configuring pagination parameters for object retrieval operations.

**Implementation Details:**
- **File:** `src/main/java/auraditor/suite/ui/ActionsTab.java`
- **Location:** Near line ~525 where other UI controls are initialized
- **New UI Components Required:**
  ```java
  private final JSpinner pageSizeSpinner; // Range: 1-1000, default: 1000
  private final JSpinner maxPagesSpinner; // Range: 1-unlimited, default: 1
  private final JLabel pageSizeLabel;
  private final JLabel maxPagesLabel;
  ```
- **UI Layout:** Add these controls in the "Get Objects" section (around line ~584)
- **Labels:**
  - "Records per page:" (for pageSizeSpinner)
  - "Maximum pages:" (for maxPagesSpinner)
- **Tooltips:**
  - "Number of records to retrieve per page (1-1000)"
  - "Maximum number of pages to process (0 = unlimited)"

## Priority 2: Core Functionality Enhancements

### 3. Dynamic Pagination System for SPECIFIC_OBJECT_PAYLOAD_TEMPLATE
**Description:** Modify the object retrieval system to support configurable pagination with automatic page iteration.

**Implementation Details:**
- **File:** `src/main/java/auraditor/suite/ui/ActionsTab.java`
- **Current Template Location:** Line ~507
- **Current Template:**
  ```java
  private static final String SPECIFIC_OBJECT_PAYLOAD_TEMPLATE = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"entityNameOrId\":\"%s\",\"layoutType\":\"FULL\",\"pageSize\":1000,\"currentPage\":0,\"useTimeout\":false,\"getCount\":false,\"enableRowActions\":false}}]}";
  ```

**Required Changes:**
1. **New Template with Placeholders:**
   ```java
   private static final String SPECIFIC_OBJECT_PAYLOAD_TEMPLATE = "{\"actions\":[{\"id\":\"100;a\",\"descriptor\":\"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems\",\"callingDescriptor\":\"UNKNOWN\",\"params\":{\"entityNameOrId\":\"%s\",\"layoutType\":\"FULL\",\"pageSize\":%d,\"currentPage\":%d,\"useTimeout\":false,\"getCount\":false,\"enableRowActions\":false}}]}";
   ```

2. **Pagination Logic:**
   - **Method:** `performSpecificObjectSearch()` (line ~2194)
   - **Method:** `performBulkObjectRetrieval()` (line ~2232)
   - **Logic:**
     - Start with page 1 (not 0)
     - Continue to next page only if current page returns exactly `pageSize` records
     - Stop when `maxPages` reached or fewer than `pageSize` records returned
     - Include page number in result tab names: "Object Results - Page 1", "Object Results - Page 2"

3. **String.format() Usage:**
   ```java
   String specificObjectPayload = String.format(SPECIFIC_OBJECT_PAYLOAD_TEMPLATE,
       escapedObjectName, pageSizeSpinner.getValue(), currentPage);
   ```

### 4. Get Accessible Apex Code Feature
**Description:** Add button to download accessible Apex code using ApexClass entity with security considerations.

**Implementation Details:**
- **File:** `src/main/java/auraditor/suite/ui/ActionsTab.java`
- **New Button:** `private final JButton getApexCodeBtn;`
- **Button Properties:**
  - **Text:** "Get Accessible Apex Code"
  - **Tooltip:** "Download accessible Apex code (ApexClass entity, pageSize limited to 25)"
  - **Location:** In "Get Objects" section (after line ~611)
  - **Enable/Disable Logic:** Same as other Get Objects buttons (line ~3848)

**Technical Implementation:**
- **Entity Name:** "ApexClass"
- **Page Size:** Fixed at 25 (security measure to prevent DoS)
- **Integration:** Call same processing logic as other object retrieval methods
- **Action Handler:** Add case for "GetApexCode" in `executeAction()` method
- **Method Call:** Use existing `performSpecificObjectSearch()` with "ApexClass" parameter

**Integration with "Get All Objects":**
- **File Reference:** Line ~3587 where `findAllObjectsBtn` logic is implemented
- **Requirement:** When "Get All Objects" is triggered, also include Apex code retrieval
- **Implementation:** Add Apex code to the `allDiscoveredObjects` collection

**Reference Links:**
- Implementation idea: https://raw.githubusercontent.com/prjblk/aura-dump/refs/heads/main/aura_dump.py
- Blog post: https://projectblack.io/blog/salesforce-penetration-testing-fundamentals/

### 5. File Content Download System
**Description:** Add capability to download file content using ContentVersion IDs from Aura responses.

**Implementation Details:**
- **File:** `src/main/java/auraditor/suite/ui/ActionsTab.java`
- **New Feature:** Parse existing JSON responses for ContentVersion IDs
- **Download URL Pattern:** `https://<instance>/sfc/servlet.shepherd/version/download/<ContentVersionId>`
- **Method Required:** Extract session cookies/auth from baseline request
- **UI Integration:** Add button or context menu option when ContentVersion records detected

**Technical Requirements:**
1. **ContentVersion Detection:**
   - Parse JSON responses for ContentVersion records
   - Look for version ID fields in existing object retrieval results
   - Pattern matching for ContentVersion-related identifiers

2. **Session Management:**
   - Extract authentication from baseline request
   - Preserve cookies and session tokens
   - Handle session timeouts gracefully

3. **Download Implementation:**
   - Send GET request to download URL
   - Handle binary content appropriately
   - Save files with proper naming convention
   - Progress tracking for large files

**Reference Links:**
- Implementation idea: https://raw.githubusercontent.com/pingidentity/AuraIntruder/refs/heads/main/aura_intruder.py
- Blog post: https://cilynx.com/penetration-testing/exposing-broken-access-controls-in-salesforce-based-applications/2047/

### 6. Enhanced Context Menu for Descriptor Results
**Description:** Add "Send to Repeater" context menu option for descriptor detail results containing full "message" parameter values.

**Implementation Details:**
- **Context:** Right-click context menu on descriptor results
- **Condition:** Only show option when:
  - Line contains full "message" parameter value
  - Baseline request exists and is selected
  - User is viewing descriptor details result

**Technical Implementation:**
- **Detection Logic:** Identify rows containing complete message parameters
- **Context Menu:** Add "Send to Repeater with Message" option
- **Action:** Create new request using baseline request but replace message parameter
- **Integration:** Use existing Burp Suite Repeater integration
- **Validation:** Ensure message parameter is well-formed before sending

## Priority 3: Existing Code TODOs

### 7. Fix Beautified JSON Parsing in AuraActionsTab
**File:** `src/main/java/auraditor/requesteditor/ui/AuraActionsTab.java`
**Location:** Line ~205-218

**Issue:** When users manually beautify JSON in the "message" parameter with proper formatting (newlines, indentation), Jackson fails to parse it with errors like "Unexpected end-of-input: expected close marker for Object"

**Root Cause:** The JSON minification logic in AuraTab.java doesn't always handle complex multiline JSON structures correctly when they contain nested objects, arrays, or escaped characters within form parameters

**Impact:** Users cannot view/edit beautified JSON in Aura Actions tab

**Current Workaround:** Users must manually minify JSON or use single-line format

**Future Fix Requirements:**
1. Properly handle nested braces and brackets in strings
2. Correctly process escaped characters within JSON strings
3. Preserve JSON structure while removing formatting whitespace
4. Handle edge cases with mixed quote types and escaped sequences

### 8. Fix Beautified JSON Parsing in AuraContextTab
**File:** `src/main/java/auraditor/requesteditor/ui/AuraContextTab.java`
**Location:** Line ~163-177

**Issue:** Similar to AuraActionsTab, when users manually beautify JSON in the "aura.context" parameter with proper formatting (newlines, indentation), the parsing logic fails with JsonProcessingException

**Root Cause:** Similar to AuraActionsTab, the JSON normalization logic doesn't handle complex multiline JSON structures correctly when they contain:
- Nested objects and arrays with formatting
- Mixed quote types and escaped characters
- Complex parameter encoding within form data

**Impact:** Users cannot view/edit beautified aura.context JSON in Context tab

**Current Workaround:** Users must manually minify JSON or use single-line format

**Future Fix Requirements:**
1. Enhanced multiline JSON detection and cleanup
2. Proper handling of URL-encoded parameters with complex JSON values
3. Better form parameter parsing for multiline content
4. Unified JSON processing across all Aura editor tabs

## Implementation Guidelines for AI Developers

### Code Style Requirements
- Follow existing Java coding conventions in the project
- Use existing error handling patterns
- Maintain consistent UI layout with GridBagLayout
- Follow existing naming conventions for buttons and methods
- Add proper JavaDoc comments for new methods
- Include detailed logging for debugging purposes

### Testing Requirements
- Test with various screen resolutions for scrollbar functionality
- Test pagination with edge cases (0 records, exactly pageSize records, etc.)
- Test ApexClass retrieval with limited privileges
- Test JSON parsing with various multiline formats
- Verify context menu appears only in appropriate conditions

### Security Considerations
- Limit ApexClass pageSize to 25 to prevent DoS
- Validate all user inputs for pagination controls
- Sanitize file names for download functionality
- Ensure session management doesn't leak credentials
- Validate JSON content before processing

### Integration Points
- Use existing `ThreadManager` for background operations
- Follow existing `setBusyState()`/`clearBusyState()` patterns
- Use existing result tab creation mechanisms
- Integrate with existing error handling and logging
- Maintain compatibility with existing preferences and settings

### Files That Will Require Modification
- `src/main/java/auraditor/suite/ui/ActionsTab.java` (main implementation)
- `src/main/java/auraditor/requesteditor/ui/AuraActionsTab.java` (JSON parsing fixes)
- `src/main/java/auraditor/requesteditor/ui/AuraContextTab.java` (JSON parsing fixes)
- Potentially new utility classes for file download and advanced JSON processing

### External Dependencies
- Ensure compatibility with existing Jackson JSON processing library
- Use existing Burp Suite Montoya API patterns
- Maintain compatibility with Java 21+ requirements
- Consider adding new dependencies only if absolutely necessary