# Auraditor

A professional Burp Suite extension for Lightning/Aura framework security testing with advanced action management, context editing, and comprehensive audit capabilities.

This is an **independent enhanced version** based on the original [salesforce/lightning-burp](https://github.com/salesforce/lightning-burp) project (now archived). Auraditor includes significant modernizations, new features, and improved usability for security testing professionals.

## ⚠️ **DISCLAIMER**

**This tool is for authorized security testing only.** 

- ❌ **NO SUPPORT**: The maintainer provides no support or warranty
- ❌ **NO LIABILITY**: The maintainer is not responsible for any damage, harm, or legal consequences
- ❌ **NO GUARANTEE**: The tool may not work properly or may cause issues
- ✅ **YOUR RESPONSIBILITY**: Users assume ALL responsibility for proper, legal, and authorized use

**Use at your own risk. Ensure you have proper authorization before testing any systems.**

Installs Aura tabs on HTTP message editors (Interceptor, Repeater, etc). Decodes and prettifies the aura actions, and makes params editable with intelligent error handling, action management, and user control over invalid JSON scenarios.

## Features

### Current Capabilities
- **Aura Actions Tab** - Individual action editing with Controller/Method fields and JSON parameter editing
- **Closeable Action Management** - Add/remove actions with intuitive tab interface
- **Smart JSON Error Handling** - User choice dialogs for handling invalid JSON scenarios  
- **Enhanced Text Editing** - Context menu with Cut/Copy/Paste and line wrapping toggle
- **Real-time Change Detection** - Immediate request updates when editing parameters
- **Dark Mode Support** - Proper theme integration with Burp Suite

*Note: Screenshots will be updated in future releases to reflect the current enhanced interface.*

## Requirements
- Java 21 or higher (required for latest Burp Suite 2025 performance optimizations)
- Burp Suite Professional 2025.x or later (for Montoya API support)

## Building

### Using Maven wrapper (Windows):
```powershell
.\mvnw.cmd clean package
```

### Using Maven wrapper (Unix/Linux/macOS):
```bash
./mvnw clean package
```

### Using Maven directly:
```bash
mvn clean package
```

### Using VS Code:
The project includes VS Code tasks for building:
- Press `Ctrl+Shift+P` and run "Tasks: Run Task"
- Select "Maven: Package" for a complete build

## Installing
In Burp Suite:
- Go to Extensions -> Installed
- Click "Add" 
- Locate the compiled jar file: `target/auraditor-*.jar`
- Click "Next" to install

## Technical Details

### Modern Technology Stack
- **Burp Suite Integration** - Built with Montoya API for maximum compatibility
- **Java 21 LTS** - Latest Java features and improved performance optimizations
- **Jackson JSON Processing** - Robust JSON parsing and manipulation
- **Swing UI Components** - Native look and feel with dark mode support

### Key Improvements Over Original
- **Complete API Modernization** - Migrated from legacy Burp API to modern Montoya API
- **Enhanced User Experience** - Closeable tabs, context menus, smart error handling
- **Better Dark Mode Support** - Proper theme integration and text visibility
- **Real-time Change Detection** - Fixed issues where edits weren't being sent to server
- **Improved Error Handling** - User choice dialogs and smart error state management

### Security Testing Features
- **Lightning/Aura Request Parsing** - Automatic detection and parsing of Aura framework requests
- **Parameter Manipulation** - Edit controller, method, and JSON parameters with validation
- **Invalid JSON Testing** - Option to send malformed JSON for edge case testing
- **Request Modification** - Real-time request updates with immediate feedback

## Contributors & Acknowledgments

**Auraditor (Professional Security Testing Tool):**
- **Soroush Dalili** ([@irsdl](https://github.com/irsdl)) - Project maintainer, enhanced features, modernization, and improvements
- **AI Collaboration** - Technical implementation, API migration, and code optimization

**Original Foundation:**
- **Salesforce.com, Inc.** - Original Lightning Burp extension development ([archived project](https://github.com/salesforce/lightning-burp))

Auraditor represents a significant evolution from the original codebase, with extensive modernization, new features, and improved user experience. While built upon the foundation of the original Salesforce project, this is an independent project with its own development direction and maintenance.

## Versioning Strategy

This project follows [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH):

- **MAJOR** (x.0.0): Breaking changes, complete API rewrites, major architectural changes
- **MINOR** (2.x.0): New features, enhancements, significant improvements (backward compatible)
- **PATCH** (2.1.x): Bug fixes, small improvements, security updates

**Release Examples:**
- `2.0.1` → `2.0.2`: Bug fixes, minor UI improvements  
- `2.0.1` → `2.1.0`: New features like additional context menus, more Lightning framework support
- `2.0.1` → `3.0.0`: Major rewrite, breaking changes to extension structure

JAR files include the full version: `auraditor-2.0.1.jar`

## Project Status

**Independent Enhanced Project** - This is a standalone project that evolved from the original Salesforce Lightning Burp extension. Key differences:

- ✅ **Active Development**: Maintained and enhanced with new features
- ✅ **Modern API**: Updated to Burp Suite Montoya API (2025.8)
- ✅ **Enhanced UX**: Closeable tabs, context menus, smart error handling
- ✅ **Independent**: Not affiliated with or supported by Salesforce
- ⚠️ **No Official Support**: Community-driven development, use at your own risk

The original [salesforce/lightning-burp](https://github.com/salesforce/lightning-burp) repository is archived and no longer maintained.

## Additional Resources & Inspiration

### Recommended Reading
- [**Salesforce Penetration Testing Fundamentals**](https://projectblack.io/blog/salesforce-penetration-testing-fundamentals/) - Comprehensive guide to Salesforce security testing methodologies
- [**Exposing Broken Access Controls in Salesforce-based Applications**](https://cilynx.com/penetration-testing/exposing-broken-access-controls-in-salesforce-based-applications/2047/) - In-depth analysis of access control vulnerabilities in Salesforce applications
- [**Misconfigured Salesforce Experiences**](https://www.varonis.com/blog/misconfigured-salesforce-experiences) - Common misconfigurations and security issues in Salesforce implementations

### Acknowledgments & Inspiration
Special thanks to the following projects for inspiration and advancing Salesforce security testing:

- **[aura-dump](https://github.com/prjblk/aura-dump)** - Innovative tool for Aura framework exploration and data extraction
- **[AuraIntruder](https://github.com/pingidentity/AuraIntruder/)** - Automated Burp Suite extension for Aura framework security testing

These projects have contributed valuable insights to the Salesforce security testing community and helped shape modern approaches to Lightning/Aura framework assessment.
