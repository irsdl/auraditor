/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;

/**
 * Tab displaying information about the Auraditor extension
 */
public class AboutTab {

    private final MontoyaApi api;
    private final JPanel mainPanel;

    // Extension information
    private static final String EXTENSION_NAME = "Auraditor";
    private static final String VERSION = "2.0.3";
    private static final String AUTHOR = "Soroush Dalili (@irsdl)";
    private static final String GITHUB_URL = "https://github.com/irsdl/auraditor";
    private static final String ISSUES_URL = "https://github.com/irsdl/auraditor/issues";
    private static final String DESCRIPTION = "Professional Burp Suite extension for Lightning/Aura framework security testing";

    public AboutTab(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new JPanel();
        this.mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        createAboutPanel();
    }

    /**
     * Create the about panel with extension information
     */
    private void createAboutPanel() {
        // Title
        JLabel titleLabel = new JLabel(EXTENSION_NAME);
        titleLabel.setFont(new Font(titleLabel.getFont().getName(), Font.BOLD, 28));
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(titleLabel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // Description
        JLabel descLabel = new JLabel(DESCRIPTION);
        descLabel.setFont(new Font(descLabel.getFont().getName(), Font.PLAIN, 12));
        descLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(descLabel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 30)));

        // Information panel
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new GridBagLayout());
        infoPanel.setAlignmentX(Component.CENTER_ALIGNMENT);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 10, 5, 10);

        // Version
        gbc.gridx = 0;
        gbc.gridy = 0;
        JLabel versionTitleLabel = new JLabel("Version:");
        versionTitleLabel.setFont(new Font(versionTitleLabel.getFont().getName(), Font.BOLD, 14));
        infoPanel.add(versionTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel versionLabel = new JLabel(VERSION);
        versionLabel.setFont(new Font(versionLabel.getFont().getName(), Font.PLAIN, 14));
        infoPanel.add(versionLabel, gbc);

        // Author
        gbc.gridx = 0;
        gbc.gridy = 1;
        JLabel authorTitleLabel = new JLabel("Author:");
        authorTitleLabel.setFont(new Font(authorTitleLabel.getFont().getName(), Font.BOLD, 14));
        infoPanel.add(authorTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel authorLabel = new JLabel(AUTHOR);
        authorLabel.setFont(new Font(authorLabel.getFont().getName(), Font.PLAIN, 14));
        infoPanel.add(authorLabel, gbc);

        // GitHub Project
        gbc.gridx = 0;
        gbc.gridy = 2;
        JLabel githubTitleLabel = new JLabel("GitHub:");
        githubTitleLabel.setFont(new Font(githubTitleLabel.getFont().getName(), Font.BOLD, 14));
        infoPanel.add(githubTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel githubLabel = createHyperlinkLabel(GITHUB_URL, GITHUB_URL);
        infoPanel.add(githubLabel, gbc);

        // Report Issue
        gbc.gridx = 0;
        gbc.gridy = 3;
        JLabel issuesTitleLabel = new JLabel("Report Issue:");
        issuesTitleLabel.setFont(new Font(issuesTitleLabel.getFont().getName(), Font.BOLD, 14));
        infoPanel.add(issuesTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel issuesLabel = createHyperlinkLabel("Submit an issue on GitHub", ISSUES_URL);
        infoPanel.add(issuesLabel, gbc);

        mainPanel.add(infoPanel);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 30)));

        // Features section
        JLabel featuresTitle = new JLabel("Key Features:");
        featuresTitle.setFont(new Font(featuresTitle.getFont().getName(), Font.BOLD, 16));
        featuresTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(featuresTitle);
        mainPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        String[] features = {
            "• Aura Actions Tab - Individual action editing with Controller/Method fields",
            "• Closeable Action Management - Add/remove actions with intuitive tab interface",
            "• Smart JSON Error Handling - User choice dialogs for invalid JSON scenarios",
            "• Enhanced Text Editing - Context menu with Cut/Copy/Paste and line wrapping",
            "• Real-time Change Detection - Immediate request updates when editing",
            "• Dark Mode Support - Proper theme integration with Burp Suite",
            "• LWC & Aura Descriptor Discovery - Extract Apex methods from JavaScript files"
        };

        JPanel featuresPanel = new JPanel();
        featuresPanel.setLayout(new BoxLayout(featuresPanel, BoxLayout.Y_AXIS));
        featuresPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        for (String feature : features) {
            JLabel featureLabel = new JLabel(feature);
            featureLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            featureLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
            featuresPanel.add(featureLabel);
            featuresPanel.add(Box.createRigidArea(new Dimension(0, 3)));
        }

        mainPanel.add(featuresPanel);

        // Add vertical glue to push content to top
        mainPanel.add(Box.createVerticalGlue());

        // Footer
        JLabel footerLabel = new JLabel("Licensed under BSD 3-Clause License");
        footerLabel.setFont(new Font(footerLabel.getFont().getName(), Font.ITALIC, 10));
        footerLabel.setForeground(Color.GRAY);
        footerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        mainPanel.add(footerLabel);
    }

    /**
     * Create a clickable hyperlink label
     */
    private JLabel createHyperlinkLabel(String text, String url) {
        JLabel label = new JLabel("<html><a href=''>" + text + "</a></html>");
        label.setFont(new Font(label.getFont().getName(), Font.PLAIN, 14));
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.setForeground(new Color(0, 102, 204)); // Blue color for links

        label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                openURL(url);
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                label.setText("<html><a href=''><u>" + text + "</u></a></html>");
            }

            @Override
            public void mouseExited(MouseEvent e) {
                label.setText("<html><a href=''>" + text + "</a></html>");
            }
        });

        return label;
    }

    /**
     * Open URL in default browser
     */
    private void openURL(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
                api.logging().logToOutput("Opened URL: " + url);
            } else {
                // Fallback: log the URL for manual opening
                api.logging().logToOutput("Please open this URL manually: " + url);
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to open URL: " + url + " - " + e.getMessage());
            api.logging().logToOutput("Please open this URL manually: " + url);
        }
    }

    /**
     * Get the main UI component for this tab
     */
    public JComponent getComponent() {
        return mainPanel;
    }
}
