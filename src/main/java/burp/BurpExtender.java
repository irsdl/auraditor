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
import auraditor.suite.ui.SalesforceIdGeneratorManager;
import auraditor.core.ThreadManager;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class BurpExtender implements BurpExtension {

	private AuraditorSuiteTab auraditorSuiteTab;
	private SalesforceIdGeneratorManager generatorManager;
	private MontoyaApi api;

	@Override
	public void initialize(MontoyaApi api) {
		this.api = api;
		api.extension().setName("Auraditor");

		// Log version and build information
		String version = "2.0.3";
		String buildDate = "2025-10-08 13:35";
		api.logging().logToOutput("=== Auraditor Extension Starting ===");
		api.logging().logToOutput("Version: " + version);
		api.logging().logToOutput("Build Date: " + buildDate);
		api.logging().logToOutput("Features: Selection preservation during scans, word wrap toggle, search highlighting, read-only base requests");

		// Register separate tab factories for Actions and Context (existing functionality)
		AuraActionsTabFactory actionsFactory = new AuraActionsTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(actionsFactory);
		api.userInterface().registerHttpResponseEditorProvider(actionsFactory);

		AuraContextTabFactory contextFactory = new AuraContextTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(contextFactory);
		api.userInterface().registerHttpResponseEditorProvider(contextFactory);

		// Initialize Salesforce ID Generator Manager
		api.logging().logToOutput("Initializing Salesforce ID Generator Manager...");
		generatorManager = new SalesforceIdGeneratorManager(api);

		// Create and register the main Auraditor suite tab
		api.logging().logToOutput("Creating Auraditor Suite Tab...");
		auraditorSuiteTab = new AuraditorSuiteTab(api, generatorManager);
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

		// Register shutdown hook to ensure proper cleanup
		api.extension().registerUnloadingHandler(this::cleanup);
	}

	/**
	 * Cleanup method called when the extension is unloaded
	 */
	private void cleanup() {
		api.logging().logToOutput("=== Auraditor Extension Cleanup Starting ===");

		try {
			// Stop all threads managed by ThreadManager
			ThreadManager.shutdown();

			// Cleanup generator manager
			if (generatorManager != null) {
				generatorManager.cleanup();
			}

			// Cleanup the main suite tab
			if (auraditorSuiteTab != null) {
				auraditorSuiteTab.cleanup();
			}

			api.logging().logToOutput("=== Auraditor Extension Cleanup Completed ===");
		} catch (Exception e) {
			api.logging().logToError("Error during cleanup: " + e.getMessage());
		}
	}
}
