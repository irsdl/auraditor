/*
 * Copyright (c) 2025, Soroush Dalili (@irsdl)
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE.txt file in the repo root
 */
package auraditor.suite.ui;

import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.net.URL;

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
    private static final String AUTHOR_URL = "https://x.com/irsdl";
    private static final String GITHUB_URL = "https://github.com/irsdl/auraditor";
    private static final String ISSUES_URL = "https://github.com/irsdl/auraditor/issues";
    private static final String DESCRIPTION = "Burp Suite extension for Lightning/Aura framework security testing";

    public AboutTab(MontoyaApi api) {
        this.api = api;

        // Main panel with centered content
        this.mainPanel = new JPanel(new GridBagLayout());
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        createAboutPanel();
    }

    /**
     * Create the about panel with extension information
     */
    private void createAboutPanel() {
        // Container for centered content
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        // Logo
        try {
            URL logoUrl = getClass().getResource("/logo.png");
            if (logoUrl != null) {
                ImageIcon originalIcon = new ImageIcon(logoUrl);
                // Scale logo to reasonable size (e.g., 150x150)
                Image scaledImage = originalIcon.getImage().getScaledInstance(150, 150, Image.SCALE_SMOOTH);
                ImageIcon logoIcon = new ImageIcon(scaledImage);
                JLabel logoLabel = new JLabel(logoIcon);
                logoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
                contentPanel.add(logoLabel);
                contentPanel.add(Box.createRigidArea(new Dimension(0, 20)));
            }
        } catch (Exception e) {
            // Logo loading failed, continue without it
            api.logging().logToError("Failed to load logo: " + e.getMessage());
        }

        // Description
        JLabel descLabel = new JLabel(DESCRIPTION);
        descLabel.setFont(new Font(descLabel.getFont().getName(), Font.PLAIN, 13));
        descLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        contentPanel.add(descLabel);
        contentPanel.add(Box.createRigidArea(new Dimension(0, 30)));

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
        versionTitleLabel.setFont(new Font(versionTitleLabel.getFont().getName(), Font.BOLD, 16));
        infoPanel.add(versionTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel versionLabel = new JLabel(VERSION);
        versionLabel.setFont(new Font(versionLabel.getFont().getName(), Font.PLAIN, 15));
        infoPanel.add(versionLabel, gbc);

        // Author
        gbc.gridx = 0;
        gbc.gridy = 1;
        JLabel authorTitleLabel = new JLabel("Author:");
        authorTitleLabel.setFont(new Font(authorTitleLabel.getFont().getName(), Font.BOLD, 16));
        infoPanel.add(authorTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel authorLabel = createHyperlinkLabel(AUTHOR, AUTHOR_URL, 15);
        infoPanel.add(authorLabel, gbc);

        // GitHub Project
        gbc.gridx = 0;
        gbc.gridy = 2;
        JLabel githubTitleLabel = new JLabel("GitHub:");
        githubTitleLabel.setFont(new Font(githubTitleLabel.getFont().getName(), Font.BOLD, 16));
        infoPanel.add(githubTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel githubLabel = createHyperlinkLabel(GITHUB_URL, GITHUB_URL, 15);
        infoPanel.add(githubLabel, gbc);

        // Report Issue
        gbc.gridx = 0;
        gbc.gridy = 3;
        JLabel issuesTitleLabel = new JLabel("Report Issue:");
        issuesTitleLabel.setFont(new Font(issuesTitleLabel.getFont().getName(), Font.BOLD, 16));
        infoPanel.add(issuesTitleLabel, gbc);

        gbc.gridx = 1;
        JLabel issuesLabel = createHyperlinkLabel("Submit an issue on GitHub", ISSUES_URL, 15);
        infoPanel.add(issuesLabel, gbc);

        contentPanel.add(infoPanel);
        contentPanel.add(Box.createRigidArea(new Dimension(0, 30)));

        // Footer
        JLabel footerLabel = new JLabel("Licensed under BSD 3-Clause License");
        footerLabel.setFont(new Font(footerLabel.getFont().getName(), Font.ITALIC, 11));
        footerLabel.setForeground(Color.GRAY);
        footerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        contentPanel.add(footerLabel);

        // Add content panel to main panel (centered)
        GridBagConstraints mainGbc = new GridBagConstraints();
        mainGbc.gridx = 0;
        mainGbc.gridy = 0;
        mainGbc.weightx = 1.0;
        mainGbc.weighty = 1.0;
        mainGbc.anchor = GridBagConstraints.CENTER;
        mainPanel.add(contentPanel, mainGbc);
    }

    /**
     * Create a clickable hyperlink label (without HTML)
     */
    private JLabel createHyperlinkLabel(String text, String url, int fontSize) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(label.getFont().getName(), Font.PLAIN, fontSize));
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        label.setForeground(new Color(0, 102, 204)); // Blue color for links

        label.addMouseListener(new MouseAdapter() {
            private String originalText = text;

            @Override
            public void mouseClicked(MouseEvent e) {
                openURL(url);
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                // Show underline by changing font
                Font currentFont = label.getFont();
                label.setFont(currentFont.deriveFont(currentFont.getStyle() | Font.ITALIC));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                // Remove underline by resetting font
                Font currentFont = label.getFont();
                label.setFont(currentFont.deriveFont(currentFont.getStyle() & ~Font.ITALIC));
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
