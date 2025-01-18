package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class ColoredTableCellRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {
        
        Component renderer = super.getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column);

        if (table.getRowCount() == 1) {
            renderer.setBackground(table.getBackground());
            renderer.setForeground(table.getForeground());
            return renderer;
        }

        // Get all values in this column
        double[] colValues = new double[table.getRowCount()];
        for (int i = 0; i < table.getRowCount(); i++) {
            Object val = table.getValueAt(i, column);
            colValues[i] = val instanceof Integer ? (Integer)val : (Double)val;
        }

        // Find min and max
        double minValue = colValues[0];
        double maxValue = colValues[0];
        for (double val : colValues) {
            minValue = Math.min(minValue, val);
            maxValue = Math.max(maxValue, val);
        }

        if (minValue != maxValue) {
            double currentValue = value instanceof Integer ? (Integer)value : (Double)value;
            float fraction = (float)((currentValue - minValue) / (maxValue - minValue));

            // Set text color
            if (fraction > 0.75) {
                renderer.setForeground(Color.WHITE);
            } else {
                renderer.setForeground(Color.BLACK);
            }

            // Calculate color components
            float red = fraction > 0.5f ? 1.0f : fraction * 2.0f;
            float green = fraction < 0.5f ? 1.0f : 2.0f - (fraction * 2.0f);
            float blue = 111f/256f;

            if (isSelected) {
                red = Math.max(0.0f, red - 0.25f);
                green = Math.max(0.0f, green - 0.25f);
                blue = Math.max(0.0f, blue - 0.25f);
            }

            renderer.setBackground(new Color(red, green, blue));
        }

        return renderer;
    }
} 