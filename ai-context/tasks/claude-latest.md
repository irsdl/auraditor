# Task Plan: Fix Documentation and Code Consistency Issues

**Agent:** Claude
**Date:** 2025-11-17
**Session ID:** 01CLWe22rtzrx4QRmstWzLXR

---

## Task Understanding

Fix inconsistencies found between project documentation files and the actual codebase. **CONSTRAINT**: Only modify documentation files (.md, .txt), do NOT touch any .java files or anything that affects the build/JAR output.

---

## Scope: Documentation Files Only

Based on the comprehensive analysis, the following inconsistencies can be fixed without touching Java source code:

### Files to Modify:
1. **ai-context/structure.md** - Fix incorrect entry point references and JAR version
2. **agent.md** - Fix Java version requirement and entry point reference
3. **TODO.md** - Update outdated line number references

### Files NOT Modified (per user constraint):
- All .java files (would affect build)
- pom.xml (build configuration)
- Any other build-related files

---

## Detailed Implementation Plan

### **Fix 1: ai-context/structure.md - Entry Point References**

**Issue:** Documentation references non-existent `Auraditor.java` as entry point
**Reality:** Actual entry point is `src/main/java/burp/BurpExtender.java`

**Changes:**

1. **Line 29** - Change from:
   ```
   ├── Auraditor.java  # Main extension entry point (implements BurpExtension)
   ```
   To:
   ```
   ├── burp/           # Burp Suite integration
   │   └── BurpExtender.java  # Extension entry point (implements BurpExtension)
   ```

2. **Line 104** - Change from:
   ```
   - **`Auraditor.java`** - Extension entry point, registers all tabs and functionality
   ```
   To:
   ```
   - **`burp/BurpExtender.java`** - Extension entry point, registers all tabs and functionality
   ```

3. **Line 146** - Change from:
   ```
   | **Extension entry point** | `src/main/java/auraditor/Auraditor.java` |
   ```
   To:
   ```
   | **Extension entry point** | `src/main/java/burp/BurpExtender.java` |
   ```

---

### **Fix 2: ai-context/structure.md - JAR Version Mismatch**

**Issue:** Documentation says version 2.0.1
**Reality:** Current version is 2.0.5 (per pom.xml)

**Changes:**

1. **Line 77** - Change:
   ```
   └── auraditor-2.0.1.jar # Final JAR file (load this in Burp Suite)
   ```
   To:
   ```
   └── auraditor-2.0.5.jar # Final JAR file (load this in Burp Suite)
   ```

2. **Line 162** - Change:
   ```
   4. Test: Load `target/auraditor-2.0.1.jar` in Burp Suite
   ```
   To:
   ```
   4. Test: Load `target/auraditor-2.0.5.jar` in Burp Suite
   ```

3. **Line 166** - Change:
   ```
   - Final JAR is at `target/auraditor-2.0.1.jar`
   ```
   To:
   ```
   - Final JAR is at `target/auraditor-2.0.5.jar`
   ```

---

### **Fix 3: agent.md - Java Version Requirement**

**Issue:** States "Java 11+" but project requires Java 21
**Reality:** pom.xml compiles with Java 21 target

**Changes:**

**Line 279** - Change from:
```markdown
## Build Requirements
- Java 11+
- Maven 3.6+
```

To:
```markdown
## Build Requirements
- Java 21 or higher (required for compilation)
- Maven 3.6+
- Burp Suite Professional 2025.x or later with Montoya API 2025.8
```

---

### **Fix 4: agent.md - Entry Point Reference**

**Issue:** Line 216 references wrong entry point file
**Reality:** Actual entry point is BurpExtender.java

**Changes:**

**Line 216** - Change from:
```markdown
- `src/main/java/auraditor/Auraditor.java` - Main extension entry point
```

To:
```markdown
- `src/main/java/burp/BurpExtender.java` - Main extension entry point
```

---

### **Fix 5: TODO.md - Outdated Line Number References**

**Issue:** Line numbers are outdated after code changes
**Reality:** Actual locations verified via grep

**Changes:**

1. **Line 44** - Change from:
   ```markdown
   - **Current Template Location:** Line ~507
   ```
   To:
   ```markdown
   - **Current Template Location:** Line 525
   ```

2. **Line 57** - Change from:
   ```markdown
   - **Method:** `performSpecificObjectSearch()` (line ~2194)
   ```
   To:
   ```markdown
   - **Method:** `performSpecificObjectSearch()` (line 2768)
   ```

3. **Line 58** - Change from:
   ```markdown
   - **Method:** `performBulkObjectRetrieval()` (line ~2232)
   ```
   To:
   ```markdown
   - **Method:** `performBulkObjectRetrieval()` (line 2806)
   ```

---

## Potential Risks

**Low Risk:**
- These are documentation-only changes
- No impact on build or runtime behavior
- No Java code modifications
- Users following outdated documentation will benefit from corrections

---

## Testing Approach

1. **Verify file modifications** - Check that only .md files were changed
2. **No build required** - Since no code changes, compilation not needed
3. **Git diff review** - Confirm changes match plan exactly

---

## Commit Message

```
Docs: fix documentation-code consistency issues

Update documentation files to match actual codebase implementation:

- ai-context/structure.md: Fix entry point references (BurpExtender.java not Auraditor.java)
- ai-context/structure.md: Update JAR version from 2.0.1 to 2.0.5
- agent.md: Fix Java requirement from 11+ to 21+
- agent.md: Fix entry point reference to BurpExtender.java
- agent.md: Add Montoya API version requirement (2025.8)
- TODO.md: Update outdated line numbers (525, 2768, 2806)

These are documentation-only fixes with no impact on build or runtime.

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Post-Completion Checklist

- [ ] All documentation files updated as planned
- [ ] Git diff reviewed and matches plan
- [ ] Changes committed with detailed message
- [ ] User approves task completion
- [ ] User approves deletion of this task plan file

---

**Status:** ⏸️ AWAITING USER APPROVAL

Once approved, I will:
1. Apply all documented fixes
2. Review changes via git diff
3. Commit with the detailed message above
4. Request approval to delete this task plan
