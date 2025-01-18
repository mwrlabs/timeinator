package burp;

import javax.swing.table.DefaultTableModel;

public class ResultsTableModel extends DefaultTableModel {
    private static final String[] COLUMN_NAMES = {
        "Payload", "Number of Requests", "Status Code", "Length (B)", "Body (B)",
        "Minimum (ms)", "Maximum (ms)", "Mean (ms)", "Median (ms)", "StdDev (ms)"
    };

    private static final Class<?>[] COLUMN_TYPES = {
        String.class,
        Integer.class,
        Integer.class,
        Integer.class,
        Integer.class,
        Integer.class,
        Integer.class,
        Double.class,
        Double.class,
        Double.class
    };

    public ResultsTableModel() {
        super(COLUMN_NAMES, 0);
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return COLUMN_TYPES[column];
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
} 