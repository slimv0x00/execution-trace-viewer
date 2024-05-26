from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem


class TaintTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super(TaintTableWidget, self).__init__(parent)
        self.taint_data = []

    def set_data(self, data):
        """Sets table data and updates it"""
        self.taint_data = data
        self.populate()

    def populate(self):
        """Fills table with data"""
        if self.taint_data is None or not self.taint_data:
            self.setRowCount(0)
        else:
            self.setRowCount(len(self.taint_data))
            for i, taint in enumerate(self.taint_data):
                self.setItem(i, 0, QTableWidgetItem(taint.get_operand_name()))
                self.setItem(i, 1, QTableWidgetItem(str(taint.get_tainted_by())))
            self.update_column_widths()

    def update_column_widths(self):
        """Updates column widths of a TableWidget to match the content"""
        self.setVisible(False)  # fix ui glitch with column widths
        self.resizeColumnsToContents()
        self.horizontalHeader().setStretchLastSection(True)
        self.setVisible(True)
