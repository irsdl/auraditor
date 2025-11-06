# Review Plan — ChatGPT

Task: Dynamic Version Logging (compatibility)

Date: 2025-11-06 13:55 UTC

What I understand
- Version should be 2.0.5 - it has been set to 2.0.6 by mistake
- Replace hardcoded version logging with a dynamic value sourced from the JAR manifest so the version is defined once in `pom.xml` and reflected everywhere.
- Do not change other items yet; just fix version logging compatibility.

Implementation approach
- Add manifest entries to final shaded JAR so runtime can read version and build date:
  - Configure `maven-shade-plugin` with `ManifestResourceTransformer` to set:
    - `Implementation-Title = Auraditor`
    - `Implementation-Version = ${project.version}`
    - `Implementation-Build-Time = ${maven.build.timestamp}`
  - Define `maven.build.timestamp.format=yyyy-MM-dd HH:mm:ss` in `pom.xml` properties.
- Update `burp/BurpExtender.java` to read version at runtime:
  - `String version = BurpExtender.class.getPackage().getImplementationVersion();`
  - Fallback: `version = (version != null ? version : "unknown")`.
- Update `burp/BurpExtender.java` to read build date at runtime from manifest:
  - Read `Implementation-Build-Time` from `META-INF/MANIFEST.MF` via classloader resources.
  - Fallback to `"unknown"` when not available (IDE runs).

Files to modify
- `pom.xml` (shade plugin: add ManifestResourceTransformer entries + build timestamp property)
- `src/main/java/burp/BurpExtender.java` (replace hardcoded version and build date logs)

Risks / considerations
- The shaded JAR must preserve the manifest; using shade’s transformer ensures this.
- In non-shaded runs (IDE), `getImplementationVersion()` may return `null`; hence the fallback.

Testing approach
- Build: `mvn clean package` and load JAR in Burp; confirm startup logs show `Version: 2.0.5` and a recent `Build Date`.
- Quick check by inspecting `META-INF/MANIFEST.MF` inside the JAR for `Implementation-Version` and `Implementation-Build-Time`.

Steps
1. Modify `pom.xml` shade plugin to add manifest entries and timestamp format.
2. Change `BurpExtender` to read the version and build date dynamically.
3. Build and verify (on your side) that logs display the expected version and build date.

Awaiting approval to implement changes.
