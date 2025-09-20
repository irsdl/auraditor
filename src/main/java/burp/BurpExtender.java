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

		// Register separate tab factories for Actions and Context (existing functionality)
		AuraActionsTabFactory actionsFactory = new AuraActionsTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(actionsFactory);
		api.userInterface().registerHttpResponseEditorProvider(actionsFactory);

		AuraContextTabFactory contextFactory = new AuraContextTabFactory(api);
		api.userInterface().registerHttpRequestEditorProvider(contextFactory);
		api.userInterface().registerHttpResponseEditorProvider(contextFactory);

		// Create and register the main Auraditor suite tab
		AuraditorSuiteTab auraditorSuiteTab = new AuraditorSuiteTab(api);
		api.userInterface().registerSuiteTab("Auraditor", auraditorSuiteTab.getComponent());

		// Register context menu provider for "Send to Auraditor"
		AuraditorContextMenuProvider contextMenuProvider = new AuraditorContextMenuProvider(auraditorSuiteTab);
		api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

		api.logging().logToOutput("Auraditor extension loaded successfully!");
		api.logging().logToOutput("- Aura Actions/Context tabs available in HTTP message editors");
		api.logging().logToOutput("- Main Auraditor tab available in suite");
		api.logging().logToOutput("- Right-click 'Send to Auraditor' available for Aura requests");
	}
}
