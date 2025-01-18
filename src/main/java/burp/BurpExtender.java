package burp;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JTabbedPane tabbedPane;
    private IMessageEditor messageEditor;
    private JTextField hostTextField;
    private JTextField portTextField;
    private JCheckBox protocolCheckBox;
    private JTextArea payloadTextArea;
    private JTextField requestsNumTextField;
    private JProgressBar progressBar;
    private ResultsTableModel resultsTableModel;
    private IHttpService httpService;
    private byte[] request;
    private IHttpRequestResponse[] contextMenuData;

    private static final String EXTENSION_NAME = "Timeinator";
    private static final String[] COLUMNS = {
        "Payload", "Number of Requests", "Status Code", "Length (B)", "Body (B)",
        "Minimum (ms)", "Maximum (ms)", "Mean (ms)", "Median (ms)", "StdDev (ms)"
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                messageEditor = callbacks.createMessageEditor(BurpExtender.this, true);
                
                Insets insets = new Insets(3, 3, 3, 3);
                JPanel attackPanel = constructAttackPanel(insets, messageEditor.getComponent());
                JPanel resultsPanel = constructResultsPanel(insets);
                JPanel aboutPanel = constructAboutPanel(insets);
                
                tabbedPane = new JTabbedPane();
                tabbedPane.addTab("Attack", attackPanel);
                tabbedPane.addTab("Results", resultsPanel);
                tabbedPane.addTab("About", aboutPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return tabbedPane;
    }

    @Override
    public IHttpService getHttpService() {
        updateClassFromUI();
        return httpService;
    }

    @Override
    public byte[] getRequest() {
        updateClassFromUI();
        return request;
    }

    @Override
    public byte[] getResponse() {
        return null;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        
        if (messages != null && messages.length == 1) {
            contextMenuData = messages;
            JMenuItem menuItem = new JMenuItem("Send to " + EXTENSION_NAME);
            menuItem.addActionListener(e -> contextMenuItemClicked());
            return Collections.singletonList(menuItem);
        }
        return null;
    }

    private void contextMenuItemClicked() {
        IHttpRequestResponse httpRequestResponse = contextMenuData[0];
        
        httpService = httpRequestResponse.getHttpService();
        request = httpRequestResponse.getRequest();

        // Update fields in tab
        hostTextField.setText(httpService.getHost());
        portTextField.setText(String.valueOf(httpService.getPort()));
        protocolCheckBox.setSelected(httpService.getProtocol().equals("https"));
        messageEditor.setMessage(request, true);
    }

    private double mean(List<Double> values) {
        double sum = 0.0;
        for (double value : values) {
            sum += value;
        }
        return sum / values.size();
    }

    private double median(List<Double> values) {
        ArrayList<Double> sortedValues = new ArrayList<>(values);
        Collections.sort(sortedValues);
        int length = sortedValues.size();
        
        if (length % 2 != 0) {
            // Odd number of values, return middle one
            return sortedValues.get(length / 2);
        } else {
            // Even number of values, return mean of middle two
            return (sortedValues.get(length / 2 - 1) + sortedValues.get(length / 2)) / 2.0;
        }
    }

    private double stdDev(List<Double> values) {
        double meanValue = mean(values);
        double sum = 0.0;
        
        for (double value : values) {
            sum += Math.pow(value - meanValue, 2);
        }
        
        double variance = sum / values.size();
        return Math.sqrt(variance);
    }

    private void startAttack(ActionEvent e) {
        // Switch to results tab
        tabbedPane.setSelectedIndex(1);

        // Clear results table
        while (resultsTableModel.getRowCount() > 0) {
            resultsTableModel.removeRow(0);
        }

        // Set progress bar to 0%
        progressBar.setValue(0);

        // Start attack in new thread
        new Thread(() -> makeHttpRequests()).start();
    }

    private void makeHttpRequests() {
        // Set class variables from values in UI
        updateClassFromUI();

        Map<String, List<Double>> responses = new HashMap<>();
        Set<String> payloads = new HashSet<>(Arrays.asList(payloadTextArea.getText().split("\n")));
        int numReq = Integer.parseInt(requestsNumTextField.getText());

        // Set progress bar max to number of requests
        progressBar.setMaximum(payloads.size() * numReq);

        for (String payload : payloads) {
            responses.put(payload, new ArrayList<>());
            
            // Replace payload markers in request
            byte[] modifiedRequest = replacePayloadMarkers(request, payload);
            modifiedRequest = updateContentLength(modifiedRequest);

            for (int i = 0; i < numReq; i++) {
                // Make request and measure time
                long startTime = System.currentTimeMillis();
                IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, modifiedRequest);
                long endTime = System.currentTimeMillis();
                double duration = endTime - startTime;

                progressBar.setValue(progressBar.getValue() + 1);
                responses.get(payload).add(duration);

                // If this was the last request for this payload, add results to table
                if (i == numReq - 1) {
                    addResultToTable(payload, numReq, response, responses.get(payload));
                }
            }
        }
    }

    private byte[] replacePayloadMarkers(byte[] request, String payload) {
        String requestString = helpers.bytesToString(request);
        requestString = requestString.replaceAll("\u00a7[^\u00a7]*\u00a7", payload);
        return helpers.stringToBytes(requestString);
    }

    private byte[] updateContentLength(byte[] request) {
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        int bodyOffset = analyzedRequest.getBodyOffset();
        int contentLength = request.length - bodyOffset;
        
        List<String> headers = analyzedRequest.getHeaders();
        List<String> newHeaders = new ArrayList<>();
        
        for (String header : headers) {
            if (!header.toLowerCase().startsWith("content-length:")) {
                newHeaders.add(header);
            }
        }
        newHeaders.add("Content-Length: " + contentLength);
        
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
        return helpers.buildHttpMessage(newHeaders, body);
    }

    private void addResultToTable(final String payload, final int numReqs, final IHttpRequestResponse response, final List<Double> timings) {
        final short statusCode = response.getResponse() != null ? 
            helpers.analyzeResponse(response.getResponse()).getStatusCode() : 0;
        
        final int contentLength;
        if (response.getResponse() != null) {
            IResponseInfo responseInfo = helpers.analyzeResponse(response.getResponse());
            int tempLength = 0;
            for (String header : responseInfo.getHeaders()) {
                if (header.toLowerCase().startsWith("content-length:")) {
                    tempLength = Integer.parseInt(header.split(": ")[1].trim());
                    break;
                }
            }
            contentLength = tempLength;
        } else {
            contentLength = 0;
        }

        SwingUtilities.invokeLater(() -> {
            // Calculate statistics inside the lambda to avoid effectively final issues
            double meanTime = Math.round(mean(timings) * 1000.0) / 1000.0;
            double medianTime = Math.round(median(timings) * 1000.0) / 1000.0;
            double stdDevTime = Math.round(stdDev(timings) * 1000.0) / 1000.0;
            int minTime = (int) Collections.min(timings).doubleValue();
            int maxTime = (int) Collections.max(timings).doubleValue();

            resultsTableModel.addRow(new Object[]{
                payload, numReqs, statusCode,
                response.getResponse() != null ? response.getResponse().length : 0,
                contentLength, minTime, maxTime, meanTime, medianTime, stdDevTime
            });
        });
    }

    private void updateClassFromUI() {
        String host = hostTextField.getText();
        int port = Integer.parseInt(portTextField.getText());
        String protocol = protocolCheckBox.isSelected() ? "https" : "http";

        // Attempt DNS resolution to cache the result
        try {
            java.net.InetAddress.getByName(host);
        } catch (Exception e) {
            // Ignore resolution failures
        }

        httpService = helpers.buildHttpService(host, port, protocol);
        request = messageEditor.getMessage();
    }

    private void addPayload(ActionEvent e) {
        byte[] currentMessage = messageEditor.getMessage();
        int[] selection = messageEditor.getSelectionBounds();
        
        if (selection[0] == selection[1]) {
            // No text selected, insert markers at cursor
            byte[] newMessage = new byte[currentMessage.length + 2];
            System.arraycopy(currentMessage, 0, newMessage, 0, selection[0]);
            newMessage[selection[0]] = (byte)0xa7;
            newMessage[selection[0] + 1] = (byte)0xa7;
            System.arraycopy(currentMessage, selection[0], newMessage, selection[0] + 2, currentMessage.length - selection[0]);
            messageEditor.setMessage(newMessage, true);
        } else {
            // Text selected, wrap with markers
            byte[] newMessage = new byte[currentMessage.length + 2];
            System.arraycopy(currentMessage, 0, newMessage, 0, selection[0]);
            newMessage[selection[0]] = (byte)0xa7;
            System.arraycopy(currentMessage, selection[0], newMessage, selection[0] + 1, selection[1] - selection[0]);
            newMessage[selection[1] + 1] = (byte)0xa7;
            System.arraycopy(currentMessage, selection[1], newMessage, selection[1] + 2, currentMessage.length - selection[1]);
            messageEditor.setMessage(newMessage, true);
        }
    }

    private void clearPayloads(ActionEvent e) {
        byte[] currentMessage = messageEditor.getMessage();
        String messageString = helpers.bytesToString(currentMessage).replace("\u00a7", "");
        messageEditor.setMessage(helpers.stringToBytes(messageString), true);
    }

    private JPanel constructAttackPanel(Insets insets, Component messageEditorComponent) {
        JPanel attackPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c;

        // Target heading
        JLabel targetHeadingLabel = new JLabel("Target");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 4;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(targetHeadingLabel, c);

        // Start Attack button
        JButton startAttackButton = new JButton("Start Attack");
        startAttackButton.addActionListener(this::startAttack);
        c = new GridBagConstraints();
        c.gridx = 4;
        c.gridy = 0;
        c.insets = insets;
        attackPanel.add(startAttackButton, c);

        // Host field
        JLabel hostLabel = new JLabel("Host:");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 1;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(hostLabel, c);

        hostTextField = new JTextField(25);
        hostTextField.setMinimumSize(hostTextField.getPreferredSize());
        c = new GridBagConstraints();
        c.gridx = 1;
        c.gridy = 1;
        c.weightx = 1;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(hostTextField, c);

        // Port field
        JLabel portLabel = new JLabel("Port:");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 2;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(portLabel, c);

        portTextField = new JTextField(5);
        portTextField.setMinimumSize(portTextField.getPreferredSize());
        c = new GridBagConstraints();
        c.gridx = 1;
        c.gridy = 2;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(portTextField, c);

        // HTTPS checkbox
        protocolCheckBox = new JCheckBox("Use HTTPS");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 3;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(protocolCheckBox, c);

        // Request heading
        JLabel requestHeadingLabel = new JLabel("Request");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 4;
        c.gridwidth = 4;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(requestHeadingLabel, c);

        // Message editor
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 5;
        c.weightx = 1;
        c.weighty = 0.75;
        c.gridwidth = 4;
        c.gridheight = 2;
        c.fill = GridBagConstraints.BOTH;
        c.insets = insets;
        attackPanel.add(messageEditorComponent, c);

        // Add/Clear payload marker buttons
        JButton addPayloadButton = new JButton("Add §");
        addPayloadButton.addActionListener(this::addPayload);
        c = new GridBagConstraints();
        c.gridx = 4;
        c.gridy = 5;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = insets;
        attackPanel.add(addPayloadButton, c);

        JButton clearPayloadButton = new JButton("Clear §");
        clearPayloadButton.addActionListener(this::clearPayloads);
        c = new GridBagConstraints();
        c.gridx = 4;
        c.gridy = 6;
        c.anchor = GridBagConstraints.PAGE_START;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = insets;
        attackPanel.add(clearPayloadButton, c);

        // Payloads section
        JLabel payloadHeadingLabel = new JLabel("Payloads");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 7;
        c.gridwidth = 4;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(payloadHeadingLabel, c);

        payloadTextArea = new JTextArea();
        JScrollPane payloadScrollPane = new JScrollPane(payloadTextArea);
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 8;
        c.weighty = 0.25;
        c.gridwidth = 3;
        c.fill = GridBagConstraints.BOTH;
        c.insets = insets;
        attackPanel.add(payloadScrollPane, c);

        // Number of requests field
        JLabel requestsNumLabel = new JLabel("Number of requests for each payload:");
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 9;
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(requestsNumLabel, c);

        requestsNumTextField = new JTextField("100", 4);
        requestsNumTextField.setMinimumSize(requestsNumTextField.getPreferredSize());
        c = new GridBagConstraints();
        c.gridx = 2;
        c.gridy = 9;
        c.anchor = GridBagConstraints.LINE_START;
        c.insets = insets;
        attackPanel.add(requestsNumTextField, c);

        return attackPanel;
    }

    private JPanel constructResultsPanel(Insets insets) {
        JPanel resultsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c;

        // Progress bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setMinimum(0);
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.fill = GridBagConstraints.HORIZONTAL;
        resultsPanel.add(progressBar, c);

        // Results table
        resultsTableModel = new ResultsTableModel();
        JTable resultsTable = new JTable(resultsTableModel);
        resultsTable.setAutoCreateRowSorter(true);
        
        // Set up cell renderer for timing columns
        ColoredTableCellRenderer cellRenderer = new ColoredTableCellRenderer();
        for (int i = 5; i <= 9; i++) {
            resultsTable.getColumnModel().getColumn(i).setCellRenderer(cellRenderer);
        }

        // Set column widths
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(99999999);
        resultsTable.getColumnModel().getColumn(1).setMinWidth(160);
        resultsTable.getColumnModel().getColumn(2).setMinWidth(100);
        resultsTable.getColumnModel().getColumn(3).setMinWidth(80);
        resultsTable.getColumnModel().getColumn(4).setMinWidth(80);
        resultsTable.getColumnModel().getColumn(5).setMinWidth(110);
        resultsTable.getColumnModel().getColumn(6).setMinWidth(110);
        resultsTable.getColumnModel().getColumn(7).setMinWidth(90);
        resultsTable.getColumnModel().getColumn(8).setMinWidth(110);
        resultsTable.getColumnModel().getColumn(9).setMinWidth(110);
        
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        
        JScrollPane resultsScrollPane = new JScrollPane(resultsTable);
        c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 1;
        c.weightx = 1;
        c.weighty = 1;
        c.fill = GridBagConstraints.BOTH;
        resultsPanel.add(resultsScrollPane, c);

        return resultsPanel;
    }

    private JPanel constructAboutPanel(Insets insets) {
        JPanel aboutPanel = new JPanel(new GridBagLayout());
        
        String aboutBody = 
            EXTENSION_NAME + "\n\n" +
            "A Burp Suite extension for timing attacks.\n\n" +
            "To use this extension:\n\n" +
            "1. Send a request to this extension using the context menu\n" +
            "2. Mark the position(s) for payload insertion using the § buttons\n" +
            "3. Enter payloads (one per line)\n" +
            "4. Click 'Start Attack'\n\n" +
            "The extension will make the specified number of requests for each payload " +
            "and display timing statistics in the Results tab.";

        JTextArea aboutTextArea = new JTextArea(aboutBody);
        aboutTextArea.setEditable(false);
        aboutTextArea.setWrapStyleWord(true);
        aboutTextArea.setLineWrap(true);
        aboutTextArea.setBackground(new Color(238, 238, 238));
        aboutTextArea.setMargin(new Insets(10, 10, 10, 10));
        
        GridBagConstraints c = new GridBagConstraints();
        c.weightx = 1;
        c.weighty = 1;
        c.insets = insets;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.PAGE_START;
        aboutPanel.add(aboutTextArea, c);

        return aboutPanel;
    }
} 