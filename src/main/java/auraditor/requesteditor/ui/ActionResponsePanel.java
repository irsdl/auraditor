/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import java.awt.BorderLayout;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.core.JsonProcessingException;

import auraditor.core.ActionResponse;

@SuppressWarnings("serial")
public class ActionResponsePanel extends ActionPanel {
	
	private MontoyaApi api;
	
	public ActionResponsePanel(ActionResponse response, MontoyaApi api){
		super(api);
		this.api = api;
		this.setLayout(new BorderLayout());
		
		this.textEditor.setEditable(false);
		try {
			this.textEditor.setText(response.getResponseString());
		} catch (JsonProcessingException e) {
			api.logging().logToError("JsonProcessingException: " + e.getMessage());
			this.textEditor.setText("Invalid JSON");
		}

		// Add the appropriate component based on editor type
		if (this.textEditor instanceof ActionPanel.HttpRequestEditorWrapper) {
			add(((ActionPanel.HttpRequestEditorWrapper) this.textEditor).getComponent());
		} else {
			add(new javax.swing.JScrollPane(this.textEditor));
		}
	}
}
