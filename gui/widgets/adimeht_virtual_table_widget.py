from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem


class AdimehtVirtualTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super(AdimehtVirtualTableWidget, self).__init__(parent)
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
            for i, taint_dict in enumerate(self.taint_data):# 딕셔너리 키 접근 ('name', 'symbol')
                name = taint_dict.get('name', 'Unknown')
                symbol = taint_dict.get('symbol', '')

                self.setItem(i, 0, QTableWidgetItem(name))
                self.setItem(i, 1, QTableWidgetItem(symbol))
            self.update_column_widths()

    def update_column_widths(self):
        """Updates column widths of a TableWidget to match the content"""
        self.setVisible(False)  # fix ui glitch with column widths
        self.resizeColumnsToContents()
        self.horizontalHeader().setStretchLastSection(True)
        self.setVisible(True)
