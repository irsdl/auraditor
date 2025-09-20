/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import auraditor.suite.AuraDetector;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu provider for adding "Send to Auraditor" option
 */
public class AuraditorContextMenuProvider implements ContextMenuItemsProvider {
    
    private final AuraditorSuiteTab auraditorTab;
    
    public AuraditorContextMenuProvider(AuraditorSuiteTab auraditorTab) {
        this.auraditorTab = auraditorTab;
    }
    
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        // Check for context menu in HTTP message editor (right-click inside request/response)
        if (event.messageEditorRequestResponse().isPresent() && 
            event.messageEditorRequestResponse().get().requestResponse() != null) {
            
            if (AuraDetector.isAuraRequest(event.messageEditorRequestResponse().get().requestResponse())) {
                JMenuItem sendToAuraditor = new JMenuItem("Send to Auraditor");
                sendToAuraditor.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // Add the request to Auraditor
                        auraditorTab.addBaseRequest(
                            event.messageEditorRequestResponse().get().requestResponse()
                        );
                    }
                });
                menuItems.add(sendToAuraditor);
            }
        }
        // Check for context menu in Proxy History table (right-click on table rows)
        else if (!event.selectedRequestResponses().isEmpty()) {
            // Check if any of the selected requests are Aura requests
            boolean hasAuraRequest = event.selectedRequestResponses().stream()
                .anyMatch(AuraDetector::isAuraRequest);
            
            if (hasAuraRequest) {
                JMenuItem sendToAuraditor = new JMenuItem("Send to Auraditor");
                sendToAuraditor.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // Add all selected Aura requests to Auraditor
                        event.selectedRequestResponses().stream()
                            .filter(AuraDetector::isAuraRequest)
                            .forEach(auraditorTab::addBaseRequest);
                    }
                });
                menuItems.add(sendToAuraditor);
            }
        }
        
        return menuItems;
    }
}
