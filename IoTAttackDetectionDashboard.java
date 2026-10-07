import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class IoTAttackDetectionDashboard extends JFrame {

  // --- Data Structures ---
  private final ConcurrentHashMap<String, Integer> ipRequestCount = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Boolean> suspiciousIPs = new ConcurrentHashMap<>();
  
  // Blacklist Map <IP Address, Block Expiry Timestamp>
  private final ConcurrentHashMap<String, Long> blockedIPs = new ConcurrentHashMap<>();
  
  // Configuration for Blocking
  private static final long BLOCK_DURATION_MS = 60000; // Ban for 60 seconds
  
  // --- Async Logging Queue ---
  private final Queue<String> logQueue = new ConcurrentLinkedQueue<>();
  private volatile boolean loggerRunning = false;
  private Thread loggerThread;

  // --- Live UI Buffer (Ring Buffer) ---
  private final List<Object[]> uiBuffer = new ArrayList<>();
  private static final int MAX_UI_ROWS = 50;
  private final Object uiLock = new Object();

  // --- Configuration ---
  private static final int DOS_THRESHOLD = 20; 
  private static final int SERVER_PORT = 8080;
  private static final int REFRESH_RATE_MS = 200; 
  
  private volatile boolean serverRunning = false;
  private ServerSocket serverSocket;
  private int totalPackets = 0;

  // --- UI Components ---
  private JTextField txtDeviceId, txtSourceIP, txtPort, txtProtocol;
  private JLabel lblTotalPackets, lblSuspiciousCount, lblBlockedCount, lblServerStatus;
  private JButton btnStartServer, btnStopServer, btnClearBlocklist;
  private DefaultTableModel packetTableModel;
  private DefaultListModel<String> alertListModel;
  private Timer refreshTimer;

  public IoTAttackDetectionDashboard() {
    setTitle("IoT Cyber Attack Detection Dashboard - Real-Time IPS");
    setSize(1100, 700);
    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    setLocationRelativeTo(null);
    setLayout(new BorderLayout(10, 10));

    initComponents();
    
    startLoggerService();
    startServer();
    startUITimer();
    
    setState(Frame.ICONIFIED);
  }

  private void initComponents() {
    JPanel leftPanel = new JPanel(new GridBagLayout());
    leftPanel.setBorder(BorderFactory.createTitledBorder("Controls"));
    leftPanel.setPreferredSize(new Dimension(300, 0));
    
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(5, 5, 5, 5);
    gbc.fill = GridBagConstraints.HORIZONTAL;

    addLabelAndField(leftPanel, gbc, 0, "Device ID:", "txtDeviceId");
    addLabelAndField(leftPanel, gbc, 1, "Source IP:", "txtSourceIP");
    addLabelAndField(leftPanel, gbc, 2, "Port:", "txtPort");
    addLabelAndField(leftPanel, gbc, 3, "Protocol:", "txtProtocol");

    gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
    JButton btnAnalyze = new JButton("Manual Analyze");
    btnAnalyze.addActionListener(e -> analyzePacketFromInput());
    leftPanel.add(btnAnalyze, gbc);

    gbc.gridy = 5;
    JPanel serverPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
    btnStartServer = new JButton("▶ Start Monitor");
    btnStartServer.setForeground(Color.GREEN);
    btnStartServer.addActionListener(e -> startServer());
    
    btnStopServer = new JButton("⏹ Stop Monitor");
    btnStopServer.setForeground(Color.RED);
    btnStopServer.setEnabled(false);
    btnStopServer.addActionListener(e -> stopServer());
    
    serverPanel.add(btnStartServer);
    serverPanel.add(btnStopServer);
    leftPanel.add(serverPanel, gbc);

    gbc.gridy = 6;
    lblServerStatus = new JLabel("Status: Initializing...");
    lblServerStatus.setFont(new Font("SansSerif", Font.BOLD, 12));
    leftPanel.add(lblServerStatus, gbc);

    gbc.gridy = 7;
    JButton btnSimDoS = new JButton("⚡ REAL DoS Simulation");
    btnSimDoS.setForeground(Color.RED);
    btnSimDoS.addActionListener(e -> simulateRealDoS());
    leftPanel.add(btnSimDoS, gbc);

    gbc.gridy = 8;
    btnClearBlocklist = new JButton("🔓 Clear All Blocks");
    btnClearBlocklist.addActionListener(e -> clearBlocklist());
    leftPanel.add(btnClearBlocklist, gbc);

    gbc.gridy = 9;
    JButton btnClear = new JButton("Clear Logs & UI");
    btnClear.addActionListener(e -> clearAll());
    leftPanel.add(btnClear, gbc);

    add(leftPanel, BorderLayout.WEST);

    JPanel rightPanel = new JPanel(new BorderLayout(10, 10));

    // Stats Header
    JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
    statsPanel.setBorder(BorderFactory.createTitledBorder("Real-time Statistics"));
    lblTotalPackets = new JLabel("Total Packets: 0");
    lblTotalPackets.setFont(new Font("SansSerif", Font.BOLD, 14));
    lblSuspiciousCount = new JLabel("Suspicious IPs: 0");
    lblSuspiciousCount.setFont(new Font("SansSerif", Font.BOLD, 14));
    lblSuspiciousCount.setForeground(Color.ORANGE);
    lblBlockedCount = new JLabel("BLOCKED IPs: 0");
    lblBlockedCount.setFont(new Font("SansSerif", Font.BOLD, 14));
    lblBlockedCount.setForeground(Color.RED);
    JLabel lblInfo = new JLabel("Monitoring Port: " + SERVER_PORT);
    lblInfo.setForeground(Color.BLUE);
    
    statsPanel.add(lblTotalPackets);
    statsPanel.add(Box.createHorizontalStrut(15));
    statsPanel.add(lblSuspiciousCount);
    statsPanel.add(Box.createHorizontalStrut(15));
    statsPanel.add(lblBlockedCount);
    statsPanel.add(Box.createHorizontalStrut(15));
    statsPanel.add(lblInfo);
    rightPanel.add(statsPanel, BorderLayout.NORTH);

    String[] columns = {"Time", "Device ID", "Source IP", "Port", "Proto", "Action Taken"};
    packetTableModel = new DefaultTableModel(columns, 0) {
      @Override
      public boolean isCellEditable(int row, int col) { return false; }
    };
    JTable table = new JTable(packetTableModel);
    table.setRowHeight(22);
    JScrollPane tableScroll = new JScrollPane(table);
    tableScroll.setBorder(BorderFactory.createTitledBorder("Live Packet Feed"));
    rightPanel.add(tableScroll, BorderLayout.CENTER);

    alertListModel = new DefaultListModel<>();
    JList<String> alertList = new JList<>(alertListModel);
    alertList.setCellRenderer(new AlertRenderer());
    JScrollPane alertScroll = new JScrollPane(alertList);
    alertScroll.setBorder(BorderFactory.createTitledBorder("Security Alerts"));
    alertScroll.setPreferredSize(new Dimension(0, 150));
    rightPanel.add(alertScroll, BorderLayout.SOUTH);

    add(rightPanel, BorderLayout.CENTER);
  }

  private void addLabelAndField(JPanel panel, GridBagConstraints gbc, int y, String labelText, String fieldName) {
    gbc.gridx = 0; gbc.gridy = y;
    panel.add(new JLabel(labelText), gbc);
    gbc.gridx = 1;
    JTextField field = new JTextField(15);
    if(fieldName.equals("txtDeviceId")) txtDeviceId = field;
    else if(fieldName.equals("txtSourceIP")) txtSourceIP = field;
    else if(fieldName.equals("txtPort")) txtPort = field;
    else if(fieldName.equals("txtProtocol")) txtProtocol = field;
    panel.add(field, gbc);
  }

  private static class AlertRenderer extends DefaultListCellRenderer {
    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean sel, boolean focus) {
      Component c = super.getListCellRendererComponent(list, value, index, sel, focus);
      if (value != null && value.toString().contains("BLOCKED")) {
        c.setForeground(Color.RED);
        c.setFont(c.getFont().deriveFont(Font.BOLD));
      } else if (value != null && value.toString().contains("CRITICAL")) {
        c.setForeground(new Color(200, 0, 0));
        c.setFont(c.getFont().deriveFont(Font.BOLD));
      } else if (value != null && value.toString().contains("INFO")) {
        c.setForeground(Color.GRAY);
      }
      return c;
    }
  }

  // ==========================================
  // AUTO-REFRESH MECHANISM
  // ==========================================

  private void startUITimer() {
    refreshTimer = new Timer(REFRESH_RATE_MS, e -> {
      synchronized (uiLock) {
        packetTableModel.setRowCount(0);
        for (Object[] row : uiBuffer) {
          packetTableModel.addRow(row);
        }
        lblTotalPackets.setText("Total Packets: " + totalPackets);
        lblSuspiciousCount.setText("Suspicious IPs: " + suspiciousIPs.size());
        lblBlockedCount.setText("BLOCKED IPs: " + blockedIPs.size());
      }
    });
    refreshTimer.start();
  }

  // ==========================================
  // BACKGROUND LOGGER SERVICE
  // ==========================================

  private void startLoggerService() {
    if (loggerRunning) return;
    loggerRunning = true;

    loggerThread = new Thread(() -> {
      File dir = new File("./iot_logs");
      if (!dir.exists()) dir.mkdirs();
      
      String dateStr = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
      String fileName = "./iot_logs/log_" + dateStr + ".txt";
      
      BufferedWriter writer = null;
      try {
        writer = new BufferedWriter(new FileWriter(fileName, true));
        
        while (loggerRunning || !logQueue.isEmpty()) {
          String logEntry = logQueue.poll();
          if (logEntry != null) {
            writer.write(logEntry);
            writer.newLine();
            writer.flush(); 
          } else {
            Thread.sleep(10); 
          }
        }
      } catch (Exception e) {
        System.err.println("Logger Error: " + e.getMessage());
      } finally {
        if (writer != null) {
          try { writer.close(); } catch (IOException ignored) {}
        }
      }
    }, "AsyncLogger");
    
    loggerThread.setDaemon(true);
    loggerThread.start();
  }

  // ==========================================
  // NETWORK SERVER LOGIC WITH BLOCKING
  // ==========================================

  private void startServer() {
    if (serverRunning) return;

    Thread serverThread = new Thread(() -> {
      try {
        serverSocket = new ServerSocket(SERVER_PORT);
        serverRunning = true;
        
        SwingUtilities.invokeLater(() -> {
          lblServerStatus.setText("Status: ✓ Running on port " + SERVER_PORT);
          lblServerStatus.setForeground(Color.GREEN);
          btnStartServer.setEnabled(false);
          btnStopServer.setEnabled(true);
          alertListModel.addElement("[INFO] System Active. Auto-blocking enabled.");
        });

        while (serverRunning) {
          Socket client = serverSocket.accept();
          
          // CRITICAL CHECK: Is this IP already blocked?
          String ip = client.getInetAddress().getHostAddress();
          if (isIPBlocked(ip)) {
             handleBlockedClient(client, ip);
          } else {
             // Process normally
             new Thread(() -> handleClient(client)).start();
          }
        }
      } catch (IOException e) {
        if (serverRunning) {
          SwingUtilities.invokeLater(() -> 
            JOptionPane.showMessageDialog(this, "Server Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
        }
      } finally {
        serverRunning = false;
        SwingUtilities.invokeLater(() -> {
          lblServerStatus.setText("Status: Stopped");
          lblServerStatus.setForeground(Color.RED);
          btnStartServer.setEnabled(true);
          btnStopServer.setEnabled(false);
        });
      }
    });
    serverThread.setDaemon(true);
    serverThread.start();
  }

  private boolean isIPBlocked(String ip) {
    Long expiry = blockedIPs.get(ip);
    if (expiry == null) return false;
    
    // Check if block has expired
    if (System.currentTimeMillis() > expiry) {
      blockedIPs.remove(ip); // Remove expired block
      return false;
    }
    return true;
  }

  private void handleBlockedClient(Socket client, String ip) {
    try {
      // Log the attempt to connect while blocked
      String timeStr = new SimpleDateFormat("HH:mm:ss").format(new Date());
      String logEntry = String.format("[%s] LEVEL: BLOCKED   | DEVICE: N/A           | IP: %-15s | PORT: %d", 
                                      timeStr, ip, client.getPort());
      logQueue.offer(logEntry);

      // Send 403 Forbidden
      java.io.PrintWriter out = new java.io.PrintWriter(client.getOutputStream(), true);
      out.println("HTTP/1.1 403 Forbidden");
      out.println("Content-Type: text/plain");
      out.println();
      out.println("Access Denied. Your IP has been temporarily blocked due to suspicious activity.");
      
      client.close();
    } catch (Exception e) {
      // Ignore
    }
  }

  private void stopServer() {
    serverRunning = false;
    loggerRunning = false;
    try {
      if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    } catch (IOException ignored) {}
    alertListModel.addElement("[INFO] Server stopped.");
  }

  private void handleClient(Socket client) {
    try {
      String ip = client.getInetAddress().getHostAddress();
      int port = client.getPort();
      
      java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(client.getInputStream()));
      String line = in.readLine(); 
      String proto = (line != null && line.contains("HTTP")) ? "HTTP" : "TCP";
      
      String deviceId = "Dev_" + ip.replace(".", "_");
      NetworkPacket packet = new NetworkPacket(deviceId, ip, port, proto);
      
      processPacketLogic(packet);

      java.io.PrintWriter out = new java.io.PrintWriter(client.getOutputStream(), true);
      out.println("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nLogged.");
      
      client.close();
    } catch (Exception e) {
      // Ignore errors
    }
  }

  // ==========================================
  // CORE PROCESSING LOGIC (WITH BLOCKING TRIGGER)
  // ==========================================

  private synchronized void processPacketLogic(NetworkPacket packet) {
    totalPackets++;
    
    // 1. Increment Request Count
    int reqs = ipRequestCount.merge(packet.sourceIP, 1, Integer::sum);
    
    String actionTaken = "ALLOWED";
    boolean isNewAlert = false;

    // 2. Check DoS Threshold
    if (reqs > DOS_THRESHOLD) {
      actionTaken = "DOES ATTACK DETECTED";
      
      // Mark as suspicious
      if (!suspiciousIPs.containsKey(packet.sourceIP)) {
        suspiciousIPs.put(packet.sourceIP, true);
        isNewAlert = true;
        
        // TRIGGER BLOCK
        long blockExpiry = System.currentTimeMillis() + BLOCK_DURATION_MS;
        blockedIPs.put(packet.sourceIP, blockExpiry);
        
        SwingUtilities.invokeLater(() -> {
          alertListModel.addElement("CRITICAL: DoS Detected! IP: " + packet.sourceIP + " -> NOW BLOCKED for 60s");
        });
      }
    }

    // 3. Check Telnet (Optional: Can also trigger block)
    if (packet.port == 23) {
      actionTaken = "TELNET PROBE";
       if (!suspiciousIPs.containsKey(packet.sourceIP)) {
        suspiciousIPs.put(packet.sourceIP, true);
        // Optional: Block Telnet probes too? Let's keep it just flagged for now unless repeated
      }
    }

    // 4. Prepare Log Entry
    String timeStr = new SimpleDateFormat("HH:mm:ss").format(new Date(packet.timestamp));
    String logEntry = String.format("[%s] LEVEL: %-10s | DEVICE: %-15s | IP: %-15s | PORT: %d", 
                                    timeStr, actionTaken, packet.deviceId, packet.sourceIP, packet.port);
    
    logQueue.offer(logEntry);

    // 5. Update UI Buffer
    synchronized (uiLock) {
      Object[] rowData = new Object[]{timeStr, packet.deviceId, packet.sourceIP, packet.port, packet.protocol, actionTaken};
      uiBuffer.add(0, rowData); 
      
      if (uiBuffer.size() > MAX_UI_ROWS) {
        uiBuffer.remove(uiBuffer.size() - 1);
      }
    }
  }

  private void analyzePacketFromInput() {
    String d = txtDeviceId.getText().trim();
    String i = txtSourceIP.getText().trim();
    String p = txtPort.getText().trim();
    String pr = txtProtocol.getText().trim();

    if (d.isEmpty() || i.isEmpty() || p.isEmpty() || pr.isEmpty()) {
      JOptionPane.showMessageDialog(this, "Fill all fields.", "Error", JOptionPane.ERROR_MESSAGE);
      return;
    }

    int portVal;
    try { portVal = Integer.parseInt(p); } 
    catch (NumberFormatException e) { 
      JOptionPane.showMessageDialog(this, "Invalid Port.", "Error", JOptionPane.ERROR_MESSAGE); 
      return; 
    }

    processPacketLogic(new NetworkPacket(d, i, portVal, pr));
    
    txtDeviceId.setText(""); txtSourceIP.setText(""); txtPort.setText(""); txtProtocol.setText("");
    txtDeviceId.requestFocus();
  }

  // ==========================================
  // REALISTIC SIMULATION (Actual Network Traffic)
  // ==========================================

  private void simulateRealDoS() {
    String targetIp = "127.0.0.1"; // Target Localhost
    int targetPort = SERVER_PORT;
    
    // We spawn a separate thread so the UI doesn't freeze while sending packets
    new Thread(() -> {
      try {
        System.out.println("Starting REAL DoS simulation against " + targetIp + ":" + targetPort);
        
        // Send 25 ACTUAL TCP connections
        for (int i = 1; i <= 25; i++) {
          Socket sock = null;
          try {
            // 1. Create a real socket connection
            sock = new Socket();
            sock.connect(new InetSocketAddress(targetIp, targetPort), 1000); // 1 sec timeout
            
            // 2. Send real HTTP header data
            OutputStream os = sock.getOutputStream();
            String payload = "GET /attack_test_" + i + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            os.write(payload.getBytes());
            os.flush();
            
            // 3. Read response (to ensure handshake completed)
            byte[] buffer = new byte[1024];
            int bytesRead = sock.getInputStream().read(buffer);
            
            // Small delay to mimic human/bot speed (optional, remove for faster flood)
            Thread.sleep(50); 
            
            System.out.println("Packet " + i + " sent. Response received.");
            
          } catch (Exception e) {
            // If blocked, the server closes the socket or returns 403. 
            // This exception might occur if the server resets the connection immediately.
            System.err.println("Packet " + i + " failed/rejected: " + e.getMessage());
          } finally {
            if (sock != null && !sock.isClosed()) {
              sock.close();
            }
          }
        }
        
        SwingUtilities.invokeLater(() -> {
          JOptionPane.showMessageDialog(this, 
              "REAL DoS Simulation Complete!\n\n" +
              "Sent 25 actual TCP packets.\n" +
              "Check the 'Live Packet Feed' and 'Security Alerts'.\n" +
              "Try refreshing http://localhost:8080 in your browser now.", 
              "Simulation Finished", JOptionPane.INFORMATION_MESSAGE);
        });

      } catch (Exception ex) {
        ex.printStackTrace();
      }
    }).start();
  }

  private void clearBlocklist() {
    blockedIPs.clear();
    suspiciousIPs.clear();
    ipRequestCount.clear(); // Reset counts so they aren't instantly re-blocked
    alertListModel.addElement("[INFO] Blocklist cleared. All IPs allowed again.");
  }

  private void clearAll() {
    clearBlocklist();
    logQueue.clear();
    synchronized (uiLock) {
      uiBuffer.clear();
    }
    packetTableModel.setRowCount(0);
    alertListModel.clear();
    totalPackets = 0;
    lblTotalPackets.setText("Total Packets: 0");
    lblSuspiciousCount.setText("Suspicious IPs: 0");
    lblBlockedCount.setText("BLOCKED IPs: 0");
    alertListModel.addElement("[INFO] Dashboard fully reset.");
  }

  @Override
  protected void processWindowEvent(java.awt.event.WindowEvent e) {
    if (e.getID() == java.awt.event.WindowEvent.WINDOW_CLOSING) {
      stopServer();
      if (refreshTimer != null) refreshTimer.stop();
    }
    super.processWindowEvent(e);
  }

  public static void main(String[] args) {
    try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } 
    catch (Exception ignored) {}

    SwingUtilities.invokeLater(() -> {
      IoTAttackDetectionDashboard dash = new IoTAttackDetectionDashboard();
      dash.setVisible(true);
    });
  }
}

class NetworkPacket {
  String deviceId, sourceIP, protocol;
  int port;
  long timestamp;

  NetworkPacket(String d, String i, int p, String pr) {
    this.deviceId = d; this.sourceIP = i; this.port = p; this.protocol = pr;
    this.timestamp = System.currentTimeMillis();
  }
}