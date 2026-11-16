
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;

public class cti_AP25110090041 extends Frame implements ActionListener {

    TextField vehicleField, rateField, sizeField, failureField;
    Checkbox mismatchBox;
    TextArea output;

    ArrayList<TrafficEvent> events = new ArrayList<TrafficEvent>();
    ArrayList<ThreatAlert> alerts = new ArrayList<ThreatAlert>();

    Button addButton, sampleButton, featureButton;
    Button detectButton, ctiButton, reportButton, clearButton;

    public cti_AP25110090041() {
        setTitle("CTI - Connected Vehicle Threat Detection");
        setSize(850, 600);
        setLayout(new BorderLayout(10, 10));

        Label heading = new Label(
            "CTI-Driven Intelligent Threat Detection",
            Label.CENTER
        );
        heading.setFont(new Font("Arial", Font.BOLD, 22));
        add(heading, BorderLayout.NORTH);

        Panel main = new Panel(new GridLayout(1, 2, 10, 10));
        Panel form = new Panel(new GridLayout(10, 1, 5, 5));

        form.add(new Label("Vehicle ID:"));
        vehicleField = new TextField("V101");
        form.add(vehicleField);

        form.add(new Label("Packet Rate (packets/sec):"));
        rateField = new TextField("20");
        form.add(rateField);

        form.add(new Label("Message Size (bytes):"));
        sizeField = new TextField("300");
        form.add(sizeField);

        form.add(new Label("Authentication Failures:"));
        failureField = new TextField("0");
        form.add(failureField);

        mismatchBox = new Checkbox("Sender identity mismatch");
        form.add(mismatchBox);

        addButton = new Button("Add Vehicle Event");
        addButton.addActionListener(this);
        form.add(addButton);

        output = new TextArea("", 25, 50, TextArea.SCROLLBARS_VERTICAL_ONLY);
        output.setEditable(false);

        main.add(form);
        main.add(output);
        add(main, BorderLayout.CENTER);

        Panel buttons = new Panel(new GridLayout(2, 4, 5, 5));

        sampleButton = new Button("Load Sample Data");
        featureButton = new Button("Extract Features");
        detectButton = new Button("Detect Threats");
        ctiButton = new Button("CTI Attribution");
        reportButton = new Button("Risk Report");
        clearButton = new Button("Clear Output");

        Button[] allButtons = {
            sampleButton, featureButton, detectButton,
            ctiButton, reportButton, clearButton
        };

        for (Button b : allButtons) {
            b.addActionListener(this);
            buttons.add(b);
        }

        add(buttons, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                dispose();
            }
        });

        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        try {
            if (e.getSource() == addButton) {
                addEvent();
            } else if (e.getSource() == sampleButton) {
                loadSampleData();
            } else if (e.getSource() == featureButton) {
                extractFeatures();
            } else if (e.getSource() == detectButton) {
                detectThreats();
            } else if (e.getSource() == ctiButton) {
                showAttribution();
            } else if (e.getSource() == reportButton) {
                riskReport();
            } else if (e.getSource() == clearButton) {
                output.setText("");
            }
        } catch (NumberFormatException ex) {
            output.setText("Please enter valid numeric values.");
        }
    }

    void addEvent() {
        String id = vehicleField.getText().trim();

        if (id.isEmpty()) {
            output.setText("Enter a Vehicle ID.");
            return;
        }

        double rate = Double.parseDouble(rateField.getText());
        int size = Integer.parseInt(sizeField.getText());
        int failures = Integer.parseInt(failureField.getText());

        TrafficEvent event = new TrafficEvent(
            id, rate, size, failures, mismatchBox.getState()
        );

        events.add(event);
        alerts.clear();

        output.setText("Vehicle event added successfully.\n");
        output.append("Vehicle ID: " + id + "\n");
        output.append("Total events: " + events.size());
    }

    void loadSampleData() {
        events.clear();
        alerts.clear();

        events.add(new TrafficEvent("V101", 20, 300, 0, false));
        events.add(new TrafficEvent("V102", 100, 300, 0, false));
        events.add(new TrafficEvent("V103", 25, 300, 4, false));
        events.add(new TrafficEvent("V104", 30, 900, 0, false));
        events.add(new TrafficEvent("V105", 25, 300, 0, true));

        output.setText("Sample vehicle dataset loaded.\n\n");

        for (TrafficEvent event : events) {
            output.append(event.toString() + "\n");
        }
    }

    void extractFeatures() {
        output.setText("VEHICLE COMMUNICATION FEATURES\n");
        output.append("--------------------------------\n");

        if (events.isEmpty()) {
            output.append("No data available. Load sample data first.");
            return;
        }

        for (TrafficEvent event : events) {
            output.append("\nVehicle: " + event.vehicleId);
            output.append("\nPacket Rate: " + event.packetRate);
            output.append("\nMessage Size: " + event.messageSize);
            output.append("\nAuthentication Failures: " + event.authFailures);
            output.append("\nIdentity Mismatch: " + event.identityMismatch);
            output.append("\n");
        }
    }

    void detectThreats() {
        alerts.clear();
        output.setText("THREAT DETECTION RESULTS\n");
        output.append("-----------------------\n");

        if (events.isEmpty()) {
            output.append("No data available. Load sample data first.");
            return;
        }

        for (TrafficEvent event : events) {
            ThreatAlert alert = ThreatDetector.detect(event);
            alerts.add(alert);

            output.append("\nVehicle: " + event.vehicleId);
            output.append("\nThreat: " + alert.threat);
            output.append("\nRisk: " + alert.risk);
            output.append("\n");
        }
    }

    void showAttribution() {
        output.setText("CYBER THREAT INTELLIGENCE ATTRIBUTION\n");
        output.append("------------------------------------\n");

        if (alerts.isEmpty()) {
            output.append("Run threat detection first.");
            return;
        }

        for (ThreatAlert alert : alerts) {
            output.append("\nVehicle: " + alert.vehicleId);
            output.append("\nDetected Threat: " + alert.threat);
            output.append("\nAttack Technique: " + alert.technique);
            output.append("\nIntelligence Source: MITRE ATT&CK reference");
            output.append("\n");
        }
    }

    void riskReport() {
        int high = 0;
        int medium = 0;
        int low = 0;

        output.setText("VEHICLE NETWORK RISK REPORT\n");
        output.append("---------------------------\n");

        if (alerts.isEmpty()) {
            output.append("Run threat detection first.");
            return;
        }

        for (ThreatAlert alert : alerts) {
            if (alert.risk.equals("HIGH")) {
                high++;
            } else if (alert.risk.equals("MEDIUM")) {
                medium++;
            } else {
                low++;
            }
        }

        output.append("Total Vehicles: " + alerts.size() + "\n");
        output.append("High Risk: " + high + "\n");
        output.append("Medium Risk: " + medium + "\n");
        output.append("Low Risk: " + low + "\n\n");

        output.append("RECOMMENDATIONS\n");
        output.append("1. Investigate high-risk vehicles.\n");
        output.append("2. Verify suspicious sender identities.\n");
        output.append("3. Monitor unusual packet rates.\n");
        output.append("4. Review authentication failures.\n");
    }

    public static void main(String[] args) {
        new cti_AP25110090041();
    }
}

class TrafficEvent {
    String vehicleId;
    double packetRate;
    int messageSize;
    int authFailures;
    boolean identityMismatch;

    TrafficEvent(String id, double rate, int size,
                 int failures, boolean mismatch) {
        vehicleId = id;
        packetRate = rate;
        messageSize = size;
        authFailures = failures;
        identityMismatch = mismatch;
    }

    public String toString() {
        return vehicleId + " | Rate: " + packetRate
            + " | Size: " + messageSize
            + " | Auth Failures: " + authFailures;
    }
}

class ThreatAlert {
    String vehicleId;
    String threat;
    String technique;
    String risk;

    ThreatAlert(String id, String t, String tech, String r) {
        vehicleId = id;
        threat = t;
        technique = tech;
        risk = r;
    }
}

class ThreatDetector {

    static ThreatAlert detect(TrafficEvent event) {

        if (event.packetRate > 50) {
            return new ThreatAlert(
                event.vehicleId,
                "Denial of Service",
                "Network Denial of Service",
                "HIGH"
            );
        }

        if (event.identityMismatch) {
            return new ThreatAlert(
                event.vehicleId,
                "Spoofing",
                "Spoofing Identity",
                "HIGH"
            );
        }

        if (event.authFailures >= 3) {
            return new ThreatAlert(
                event.vehicleId,
                "Unauthorized Access",
                "Valid Account / Authentication Abuse",
                "MEDIUM"
            );
        }

        if (event.messageSize > 700) {
            return new ThreatAlert(
                event.vehicleId,
                "Malicious Message Injection",
                "Command or Message Injection",
                "HIGH"
            );
        }

        return new ThreatAlert(
            event.vehicleId,
            "Normal Activity",
            "No suspicious technique identified",
            "LOW"
        );
    }
}
