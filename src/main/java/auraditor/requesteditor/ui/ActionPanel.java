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

@SuppressWarnings("serial")
public class ActionPanel extends JPanel {
	public JTextArea textEditor;
	
	public ActionPanel(){
		this.textEditor = new JTextArea();
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
		textEditor.addMouseListener(new MouseAdapter() {
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
}
