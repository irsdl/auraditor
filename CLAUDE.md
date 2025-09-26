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

### Before Writing Code:
1. **Check the Montoya API documentation** for existing functionality
2. **Search the GitHub repository** for examples and patterns
3. **DO NOT reinvent** functionality that already exists in Montoya
4. **DO NOT hallucinate** API methods - always verify they exist in the documentation

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