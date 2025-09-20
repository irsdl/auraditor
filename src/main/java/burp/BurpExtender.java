/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package burp;

import auraditor.requesteditor.ui.AuraActionsTabFactory;
import auraditor.requesteditor.ui.AuraContextTabFactory;
import auraditor.suite.ui.AuraditorContextMenuProvider;
import auraditor.suite.ui.AuraditorSuiteTab;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class BurpExtender implements BurpExtension {

	@Override
	public void initialize(MontoyaApi api) {
		api.extension().setName("Auraditor");

		// Log version and build information
		String version = "2.0.1";
		String buildDate = "2025-09-20 21:12";
		api.logging().logToOutput("=== Auraditor Extension Starting ===");
		api.logging().logToOutput("Version: " + version);
		api.logging().logToOutput("Build Date: " + buildDate);
		api.logging().logToOutput("Features: Enhanced cancel button, filtering fixes, Add Latest Compatible Request button (non-blocking UI + color annotation filtering)");

		// Register separate tab factories for Actions and Context (existing functionality)
		AuraActionsTabFactory actionsFactory = new AuraActionsTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(actionsFactory);
		api.userInterface().registerHttpResponseEditorProvider(actionsFactory);

		AuraContextTabFactory contextFactory = new AuraContextTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(contextFactory);
		api.userInterface().registerHttpResponseEditorProvider(contextFactory);

		// Create and register the main Auraditor suite tab
		api.logging().logToOutput("Creating Auraditor Suite Tab...");
		AuraditorSuiteTab auraditorSuiteTab = new AuraditorSuiteTab(api);
		api.userInterface().registerSuiteTab("Auraditor", auraditorSuiteTab.getComponent());
		api.logging().logToOutput("Auraditor Suite Tab registered successfully");

		// Register context menu provider for "Send to Auraditor"
		AuraditorContextMenuProvider contextMenuProvider = new AuraditorContextMenuProvider(auraditorSuiteTab);
		api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

		api.logging().logToOutput("=== Auraditor Extension Loaded Successfully! ===");
		api.logging().logToOutput("- Aura Actions/Context tabs available in HTTP message editors");
		api.logging().logToOutput("- Main Auraditor tab available in suite (with 'Add Latest Compatible Request' button)");
		api.logging().logToOutput("- Right-click 'Send to Auraditor' available for Aura requests");
		api.logging().logToOutput("=====================================");
	}
}
