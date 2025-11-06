# Auraditor Development Guide for AI Assistants

## Project Overview
Auraditor is a Burp Suite extension for testing Salesforce Lightning applications. It uses the Montoya API for Burp Suite integration.

## Essential Development Workflow
When making ANY changes to this project, you MUST follow this workflow:

1. **Make your changes** to the Java source files
2. **Compile and test** with: `mvn clean compile`
3. **Package the JAR** with: `mvn clean package`
4. **Commit changes** with: `git add . && git commit -m "Description of changes"`

The final JAR file will be at `target/auraditor-2.0.1.jar` - this is what users load into Burp Suite.

## Critical Resources - READ THESE FIRST

### Montoya API Documentation
- **Official Javadoc**: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html
- **GitHub Repository**: https://github.com/PortSwigger/burp-extensions-montoya-api
- **Local API Source**: [external-refs/montoya-api/](external-refs/montoya-api/) - Complete Montoya API source code (git submodule)
- **Local Examples**: [external-refs/montoya-api-examples/](external-refs/montoya-api-examples/) - Official example extensions (git submodule)

### Before Writing Code:
1. **Check the local Montoya API source** in [external-refs/montoya-api/](external-refs/montoya-api/) for existing functionality and implementation details
2. **Search the local examples** in [external-refs/montoya-api-examples/](external-refs/montoya-api-examples/) for patterns and sample code
3. **DO NOT reinvent** functionality that already exists in Montoya
4. **DO NOT hallucinate** API methods - always verify they exist in the local source or documentation
5. If needed, consult the online Javadoc for detailed method signatures and usage

### Updating External References:
The external reference repositories are git submodules and can be updated with:
```bash
git submodule update --remote
```
Or use the provided update script: `update-external-refs.cmd`

## Key Architecture Points

### Main Files:
- `src/main/java/auraditor/Auraditor.java` - Main extension entry point
- `src/main/java/auraditor/suite/ui/ActionsTab.java` - Primary UI and functionality
- `src/main/java/auraditor/requesteditor/ui/` - Request/response editor tabs

### Core Patterns:
- Use `MontoyaApi` for all Burp integration
- Use `SwingUtilities.invokeLater()` for UI updates from background threads
- Use `ThreadManager.createManagedThread()` for background operations
- Handle cancellation with boolean flags in long-running operations

### UI Components:
- Main extension uses `JTabbedPane` with multiple tabs
- Background operations show progress with button text updates
- Results displayed in `RouteDiscoveryResult` format with categorized lists

## Testing Commands
```bash
# Compile only (fast check)
mvn clean compile

# Full package build (creates JAR)
mvn clean package

# Git workflow
git add .
git commit -m "Description of changes"
```

## Common Patterns in This Codebase

### Background Operations:
```java
ThreadManager.createManagedThread(() -> {
    // Background work here
    SwingUtilities.invokeLater(() -> {
        // UI updates here
    });
}, "ThreadName").start();
```

### Results Management:
```java
RouteDiscoveryResult results = new RouteDiscoveryResult();
results.addRouteCategory("Category Name", routeList);
// Display in results panel
```

### HTTP Request Processing:
```java
HttpRequestResponse requestResponse = /* from sitemap/proxy */;
if (requestResponse.response().statedMimeType() == MimeType.SCRIPT) {
    // Process JavaScript response
}
```

## Important Notes
- Always use Montoya API patterns from the documentation
- Never guess at API method names or signatures
- Check existing code patterns before implementing new features
- Test compilation before committing
- The extension targets Burp Suite Professional with Montoya API support

## Build Requirements
- Java 11+
- Maven 3.6+
- Dependencies are managed in `pom.xml` with Maven Shade plugin for packaging

## BApp Store Compliance

### Official Documentation
- **Submission Guide**: https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-submitting-extensions
- **Acceptance Criteria**: https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria

### Functional Requirements (MUST COMPLY)
1. **Unique Functionality**: Extension must perform a function not already available
2. **Clear Naming**: Use descriptive, meaningful names
3. **Include Dependencies**: All required dependencies must be bundled
4. **Offline Support**: Must work without external network dependencies
5. **Scale Well**: Handle large projects effectively

### Technical Requirements (MUST COMPLY)
1. **Threading**: Use background threads to maintain UI responsiveness
   - ✅ Implemented via `ThreadManager.createManagedThread()`
   - ✅ UI updates via `SwingUtilities.invokeLater()`

2. **Clean Unload**: Release all resources when extension unloads
   - ✅ Implemented in `BurpExtender.cleanup()` method
   - ✅ `ThreadManager.shutdown()` stops all managed threads

3. **Burp Networking**: Use Burp's networking methods for HTTP requests
   - ✅ All HTTP operations use Montoya API (`api.http()`)

4. **Montoya API**: Must use `montoya-api` artifact
   - ✅ Configured in `pom.xml` as provided dependency

5. **GUI Parent Frame**: Create GUI elements with proper parent frame
   - ✅ All dialogs and UI components use proper parent references
   - ✅ See `AuraditorSuiteTab` constructor and dialog creation

6. **AI Functionality**: Use Montoya API for AI features (if applicable)
   - N/A - Extension does not use AI features

### Security Requirements (MUST COMPLY)
1. **Secure Operations**: Operate securely with untrusted HTTP content
   - ✅ All user input is validated and sanitized
   - ✅ URL parsing wrapped in try-catch blocks

2. **Thread Safety**: Protect shared data structures with locks
   - ✅ Thread-safe collections used where appropriate
   - ✅ UI updates properly synchronized via Swing EDT

3. **Exception Handling**: Handle exceptions in background threads
   - ✅ All background operations have try-catch blocks
   - ✅ Errors logged via `api.logging().logToError()`

4. **No Active Operations in Passive Mode**: Avoid communication to target in passive audit methods
   - ✅ Passive operations (descriptor discovery) only read from sitemap
   - ✅ Active operations clearly separated and require user action

### Performance Guidelines (SHOULD COMPLY)
1. **Avoid EDT Blocking**: Don't perform slow operations in Swing Event Dispatch Thread
   - ✅ Long operations run in background threads
   - ✅ Progress updates via `SwingUtilities.invokeLater()`

2. **Memory Management**: Don't keep long-term references to transient objects
   - ✅ Request/response data not stored long-term
   - ✅ Results displayed and then released

3. **Large Data Sets**: Be cautious with methods like `SiteMap.requestResponses()`
   - ✅ Sitemap queries filtered by URL patterns
   - ✅ Progress tracking prevents UI freezing

### Submission Process
When ready to submit to BApp Store:

1. **Verify Compliance**: Review all requirements above
2. **Prepare Repository**: Ensure GitHub repo has:
   - Complete source code
   - Clear README with usage instructions
   - Build instructions (Maven commands)
   - License file (BSD-3-Clause)

3. **Submit via Email**: Send to support@portswigger.net with:
   - GitHub repository link
   - Extension name: "Auraditor"
   - Detailed description of functionality
   - Usage instructions

4. **Review Process**: PortSwigger will:
   - Compile and review the code
   - Check for unique functionality
   - Run automated and manual tests
   - Scan for antivirus/malware issues
   - Communicate with developer for any issues

### Compliance Checklist
- [x] Uses Montoya API exclusively
- [x] Background threads for long operations
- [x] Clean unload with resource cleanup
- [x] GUI elements have parent frames
- [x] Exception handling in all threads
- [x] No EDT blocking
- [x] Thread-safe data structures
- [x] Secure handling of HTTP content
- [x] Passive operations don't communicate with target
- [x] All dependencies bundled in JAR
- [x] Clear, descriptive naming
- [x] Works offline (no external network dependencies)