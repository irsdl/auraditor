# Auraditor Development Guide for AI Assistants

## 🚨 MANDATORY FIRST STEP - TASK PLANNING 🚨

**BEFORE DOING ANYTHING ELSE**, you MUST:

1. ✍️ **CREATE** a detailed implementation plan in [ai-context/tasks/latest.md](ai-context/tasks/latest.md)
2. 📅 **INCLUDE** date/time stamp in the plan
3. 📋 **DOCUMENT**:
   - What you understand the task to be
   - Step-by-step implementation approach
   - Files that will be modified
   - Potential risks or considerations
   - Testing approach
4. ⏸️ **WAIT** for user approval before proceeding
5. ✅ **DELETE** the plan file only after task completion and user satisfaction

**⛔ DO NOT SKIP THIS STEP - NO EXCEPTIONS ⛔**

If you proceed with implementation without creating this plan first, you are violating the development workflow.

---

## START HERE - Project Structure
**FIRST**: Read [ai-context/structure.md](ai-context/structure.md) for a complete overview of the project folder structure, file locations, and where to find specific functionality. This will save time and tokens by giving you immediate context.

**Temporary Files**: If you need to reference screenshots, code samples, or other temporary files, ask the user to place them in [ai-context/temp/](ai-context/temp/) for easy access.

## Project Overview
Auraditor is a Burp Suite extension for testing Salesforce Lightning applications. It uses the Montoya API for Burp Suite integration.

## Essential Development Workflow
When making ANY changes to this project, you MUST follow this workflow:

1. **Create implementation plan** in [ai-context/tasks/latest.md](ai-context/tasks/latest.md) and wait for approval
2. **Make your changes** to the Java source files
3. **Compile and test** with: `mvn clean compile`
4. **Package the JAR** with: `mvn clean package`
5. **Commit changes** with: `git add . && git commit -m "Description of changes"`

The final JAR file will be at `target/auraditor-2.0.6.jar` - this is what users load into Burp Suite.

## Critical Resources - READ THESE FIRST

### Montoya API Documentation
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

---

## AI Development Guidelines

### Task Planning & Approval Process

**CRITICAL**: Before implementing any task:
1. **Write a detailed implementation plan** in a markdown file with date/time stamp
2. **Store the plan** in [ai-context/tasks/latest.md](ai-context/tasks/latest.md) for review
3. **Wait for user approval** before proceeding with implementation
4. **Delete the plan file** once the task is completed and user is satisfied

### Large Task Management

⚠️ **WARNING**: Having AI implement large tasks is a recipe for failure!

**Before starting any large task**:
- **Remind the user** about the risks of large AI implementations
- **Get explicit approval** before proceeding
- **Break tasks into smaller pieces** using a task tree decomposition approach
- **Decompose until leaves are simple** enough for AI to implement reliably
- **Be super prescriptive** with clear objectives, detailed requirements, and explicit examples

**Use branching** when:
- Changes need to be done in different ways to compare options
- You're not sure about a change and want to explore alternatives
- **Remind the user about branching** when these situations arise

### Code Quality Standards

**Excellence is non-negotiable**:
- ✨ **Conciseness** - Write clear, compact code without verbosity
- 📖 **Readability** - Code should be self-documenting and easy to understand
- 🎯 **Elegance** - Prefer simple, beautiful solutions over complex ones
- 🔄 **Consistency** - Follow existing patterns and naming conventions
- 📏 **Smallest solutions** - Always use the minimal approach to achieve goals

### Design Principles

**File Management**:
- ❌ **DO NOT create files longer than 2000 lines**
- ✅ **Break into multiple modular files** instead
- ⚠️ **If this changes the design, GET APPROVAL FIRST**

**Code Structure**:
- ❌ **Avoid heavily nested calls or functions**
- ✅ **Keep code flat and modular**
- ✅ **Use clear, descriptive names** (not "Tab 1", "Module 2", etc.)

### Change Management & Git

**Every change must be tracked**:
- 📝 **Create detailed commit messages** explaining:
  - WHAT changed
  - WHY it was changed (rationale and context)
  - Makes rollback decisions easier
- 🔍 **Use git for all tracking** to maintain complete history

### Safety & Constraints

**ABSOLUTE RULES - No exceptions without approval**:

1. **Libraries & Frameworks**
   - ❌ DO NOT add new libraries or frameworks without explicit approval
   - ✅ Provide justification when requesting new dependencies

2. **Module Interfaces**
   - ❌ DO NOT change existing module interfaces without explicit approval
   - ⚠️ Interface changes can break dependent code

3. **Regular Expressions**
   - ❌ NEVER change existing regex patterns unless explicitly asked
   - ⚠️ If in doubt, ASK THE USER before proceeding

4. **Unrelated Modules**
   - ❌ DO NOT touch modules not defined by the task
   - ℹ️ If you identify an error elsewhere, INFORM THE USER and let them decide

### Testing Requirements

**Test-Driven Approach**:

1. **Write test plans BEFORE code**:
   - Unit tests for individual functions
   - Mock tests for dependencies
   - Regression tests for existing functionality
   - Store tests in a separate directory

2. **Test Quality Assurance**:
   - ✅ Check test quality after writing
   - 👁️ **Remind user to eyeball the tests** themselves
   - ⚠️ **NEVER disable, remove, or change test suites** without user confirmation

3. **Test Execution Strategy**:
   - 💰 **Running tests separate from AI saves money**
   - ✅ Implement separate test execution when possible
   - 📊 Tests should be runnable independently after changes

### MCP Integration

**Leverage MCP when beneficial**:
- 🔍 **Identify opportunities** to use Model Context Protocol
- 💡 **Example**: UI design MCP can provide visual feedback instead of working blind
- ✋ **Ask user to provide** the appropriate MCP when identified
- 📢 **Clearly explain** what MCP would help and why

### Naming Conventions

**Be explicit and clear**:
- ✅ Use descriptive names: `ActionsTab`, `SitemapSearchTab`, `ResultsManager`
- ❌ Avoid generic names: "Tab 1", "Module 2", "Handler 3"
- 📛 Names should reveal intent and purpose

---

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

---

## Maintenance Reminder

**IMPORTANT**: When you add, remove, or significantly reorganize folders or major files in this project, update [ai-context/structure.md](ai-context/structure.md) to reflect the changes. This keeps AI agents informed of the current project organization and prevents confusion.