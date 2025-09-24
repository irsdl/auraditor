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
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest;

@SuppressWarnings("serial")
public class ActionPanel extends JPanel {
	public HttpRequestEditor httpEditor;
	public JTextArea textEditor; // Compatibility wrapper
	private MontoyaApi api;

	public ActionPanel(){
		this(null);
	}

	public ActionPanel(MontoyaApi api){
		this.api = api;
		if (api != null) {
			this.httpEditor = api.userInterface().createHttpRequestEditor();
			this.textEditor = new HttpRequestEditorWrapper(httpEditor);
		} else {
			this.textEditor = new JTextArea();
		}
		// Enable line wrapping for better JSON readability
		this.textEditor.setLineWrap(true);
		this.textEditor.setWrapStyleWord(true);
		
		// Add custom context menu
		setupContextMenu();
	}
	
	/**
	 * Setup custom right-click context menu for the text editor
	 */
	private void setupContextMenu() {
		JPopupMenu contextMenu = new JPopupMenu();
		
		// Cut menu item
		JMenuItem cutItem = new JMenuItem("Cut");
		cutItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				textEditor.cut();
			}
		});
		
		// Copy menu item
		JMenuItem copyItem = new JMenuItem("Copy");
		copyItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				textEditor.copy();
			}
		});
		
		// Paste menu item
		JMenuItem pasteItem = new JMenuItem("Paste");
		pasteItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				textEditor.paste();
			}
		});
		
		// Separator
		contextMenu.addSeparator();
		
		// Toggle line wrapping menu item
		JMenuItem toggleWrapItem = new JMenuItem("Toggle Line Wrapping");
		toggleWrapItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				boolean currentWrap = textEditor.getLineWrap();
				textEditor.setLineWrap(!currentWrap);
				textEditor.setWrapStyleWord(!currentWrap);
			}
		});
		
		// Add items to menu
		contextMenu.add(cutItem);
		contextMenu.add(copyItem);
		contextMenu.add(pasteItem);
		contextMenu.add(toggleWrapItem);
		
		// Add mouse listener to show context menu
		JComponent editorComponent = (textEditor instanceof HttpRequestEditorWrapper)
				? ((HttpRequestEditorWrapper) textEditor).getComponent()
				: textEditor;
		editorComponent.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				maybeShowPopup(e);
			}
			
			@Override
			public void mouseReleased(MouseEvent e) {
				maybeShowPopup(e);
			}
			
			private void maybeShowPopup(MouseEvent e) {
				if (e.isPopupTrigger()) {
					// Update menu item states based on current selection and clipboard
					cutItem.setEnabled(textEditor.getSelectedText() != null && textEditor.isEditable());
					copyItem.setEnabled(textEditor.getSelectedText() != null);
					pasteItem.setEnabled(textEditor.isEditable());
					
					contextMenu.show(e.getComponent(), e.getX(), e.getY());
				}
			}
		});
	}
	
	public byte[] getSelectedText(){
		String selectedText = textEditor.getSelectedText();
		return selectedText != null ? selectedText.getBytes() : null;
	}

	/**
	 * Wrapper class to provide JTextArea compatibility for HttpRequestEditor
	 */
	public class HttpRequestEditorWrapper extends JTextArea {
		private final HttpRequestEditor editor;
		private HttpRequest currentRequest;

		public HttpRequestEditorWrapper(HttpRequestEditor editor) {
			this.editor = editor;
			// Create a default HTTP request template for JSON content
			this.currentRequest = HttpRequest.httpRequestFromUrl("http://example.com")
					.withBody("{}");
			this.editor.setRequest(currentRequest);
		}

		@Override
		public void setText(String text) {
			if (text == null) text = "";

			// Create HTTP request with JSON body
			String httpRequestString = "POST /aura HTTP/1.1\r\n" +
					"Host: example.com\r\n" +
					"Content-Type: application/json\r\n" +
					"Content-Length: " + text.getBytes().length + "\r\n" +
					"\r\n" + text;

			try {
				this.currentRequest = HttpRequest.httpRequest(httpRequestString);
				editor.setRequest(currentRequest);
			} catch (Exception e) {
				// Fallback to simple request if parsing fails
				this.currentRequest = HttpRequest.httpRequestFromUrl("http://example.com")
						.withBody(text);
				editor.setRequest(currentRequest);
			}
		}

		@Override
		public String getText() {
			return editor.getRequest().body().toString();
		}

		@Override
		public String getSelectedText() {
			if (editor.selection().isPresent()) {
				return editor.selection().get().contents().toString();
			}
			return null;
		}

		@Override
		public void setEditable(boolean editable) {
			// HttpRequestEditor is always editable, so we ignore this
		}

		@Override
		public boolean isEditable() {
			return true;
		}

		@Override
		public void cut() {
			// Not directly supported by HttpRequestEditor
		}

		@Override
		public void copy() {
			// Not directly supported by HttpRequestEditor
		}

		@Override
		public void paste() {
			// Not directly supported by HttpRequestEditor
		}

		@Override
		public void setLineWrap(boolean wrap) {
			// Not applicable to HttpRequestEditor
		}

		@Override
		public boolean getLineWrap() {
			return false;
		}

		@Override
		public void setWrapStyleWord(boolean word) {
			// Not applicable to HttpRequestEditor
		}

		public JComponent getComponent() {
			return (JComponent) editor.uiComponent();
		}
	}
}
