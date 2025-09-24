/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.requesteditor.ui;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.RawEditor;

@SuppressWarnings("serial")
public class ActionPanel extends JPanel {
	public RawEditor rawEditor;
	public JTextArea textEditor; // Keep for backwards compatibility with existing code

	public ActionPanel(MontoyaApi api){
		// Create Burp's RawEditor for JSON syntax highlighting and line numbers
		this.rawEditor = api.userInterface().createRawEditor();

		// Create a compatibility wrapper for existing code that expects JTextArea
		setupCompatibilityWrapper();
	}

	/**
	 * Get the RawEditor component for adding to layouts
	 */
	public java.awt.Component getEditorComponent() {
		return rawEditor.uiComponent();
	}
	
	/**
	 * Setup compatibility wrapper to make existing code work with RawEditor
	 */
	private void setupCompatibilityWrapper() {
		// Create a proxy JTextArea that delegates to RawEditor
		this.textEditor = new JTextArea() {
			@Override
			public void setText(String text) {
				rawEditor.setContents(burp.api.montoya.core.ByteArray.byteArray(text));
			}

			@Override
			public String getText() {
				return rawEditor.getContents().toString();
			}

			@Override
			public void setEditable(boolean editable) {
				rawEditor.setEditable(editable);
			}

			@Override
			public boolean isEditable() {
				// RawEditor doesn't expose isEditable method, track state ourselves
				return true; // Assume editable for now
			}

			@Override
			public String getSelectedText() {
				java.util.Optional<burp.api.montoya.ui.Selection> selection = rawEditor.selection();
				return selection.isPresent() ? selection.get().contents().toString() : null;
			}

			@Override
			public void cut() {
				// RawEditor handles cut/copy/paste through standard UI
			}

			@Override
			public void copy() {
				// RawEditor handles cut/copy/paste through standard UI
			}

			@Override
			public void paste() {
				// RawEditor handles cut/copy/paste through standard UI
			}
		};
	}

	/**
	 * Setup custom right-click context menu (now handled by RawEditor automatically)
	 */
	private void setupContextMenu() {
		// RawEditor provides built-in context menus with cut/copy/paste/etc.
		// No additional setup needed
	}
	
	public byte[] getSelectedText(){
		String selectedText = textEditor.getSelectedText();
		return selectedText != null ? selectedText.getBytes() : null;
	}
}
