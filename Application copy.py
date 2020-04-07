import sys
import re

import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode

from PySide2.QtWidgets import QStatusBar
from PySide2.QtWidgets import QTableView 
from PySide2.QtWidgets import QHeaderView
from PySide2.QtWidgets import QAbstractScrollArea
from PySide2.QtWidgets import QTableWidgetItem
from PySide2.QtWidgets import QHBoxLayout
from PySide2.QtWidgets import QApplication
from PySide2.QtWidgets import QWidget
from PySide2.QtWidgets import QSizePolicy
from PySide2.QtWidgets import QTabWidget
from PySide2.QtWidgets import QAction
from PySide2.QtWidgets import QMainWindow
from PySide2.QtWidgets import QMenuBar
from PySide2.QtWidgets import QMenu
from PySide2.QtWidgets import QTableWidget
from PySide2.QtWidgets import QDialog
from PySide2.QtWidgets import QMessageBox
from PySide2.QtWidgets import QFileDialog


#This global variable holds rule class objects.
rule_list=[]
sidrev =[]

#These is the counters for the import function. 
total_import_counter = 0
ignore_import_counter = 0
new_import_counter = 0
enabled_import_counter = 0
disabled_import_counter = 0

#This global variable holds the import file variable
inputfile = "community.rules"
outputfile = ""

#This class specifies all parts of the snort rule. This allows for data to be stored in memory before transfering to database.

class Rule():

    def __init__(self,rule_status="",sid="",rev="",action="",protocol="",src_network="",src_pt="",dst_network="",dst_pt="",rule_body="", exists_in_db=False):
        self.rule_status = rule_status 
        self.sid = sid
        self.rev = rev
        self.action = action
        self.protocol = protocol
        self.src_network = src_network
        self.src_pt = src_pt
        self.dst_network = dst_network
        self.dst_pt = dst_pt
        self.rule_body = rule_body 

        self.exists_in_db = exists_in_db

# This is the function to export rulesets, this will be modifyed as it needs to show filtered results. 
    def check_if_table_empty(self):

        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()
        Test = sql_cursor.execute("SELECT count(*) FROM rules.rulesets")
        connection.close()
        
        
        if Test == None:
                return True
        else:
                return False

    def transfer_to_database(self):

        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()

        for rule in rule_list:

                if rule.exists_in_db == True:
                        print("no rule transfered")
                        pass

                else:
                
                        insert_qry = "INSERT INTO rules.rulesets (rulestatus, sid, rev, action, protocol, src_network, src_port, dst_network, dst_port, rule_body) VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                        values = (rule.rule_status, rule.sid, rule.rev, rule.action, rule.protocol, rule.src_network, rule.src_pt, rule.dst_network, rule.dst_pt,rule.rule_body)
                        sql_cursor.execute(insert_qry, values)
                        connection.commit()
                        print("commit")
        
        connection.close()

    def compare_database_to_rulelist(self):

        for i in rule_list:
                if i.exists_in_db == True:
                        pass
       
                else:
                        for j in sidrev:
                            if i.sid == int(j[0]) and i.rev <= int(j[1]):
                                i.exists_in_db = True
                     
        for i in rule_list:
                print(i.sid, i.exists_in_db)  

    def get_sidrev_from_database(self):

        global sidrev
        
        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()
        
        sid_list = []
        rev_list = []
        

        sql_cursor.execute("SELECT sid,rev FROM rules.rulesets")
     
        for x in sql_cursor:

                sid_list.append(x[0])
                rev_list.append(x[1])
        
        connection.close()

        sidrev = tuple(zip(sid_list,rev_list))
        print("sidrev Complete")
        

    def create_list(self):
        global inputfile

        Importfile = open(inputfile, 'r')
        
        for line in Importfile:

                regex_Hashes = re.findall(r'^#',line)
                regex_emptyline = re.findall(r'^\s',line)
                regex_sid = re.findall(r'(?<=sid:)\d+',line)
                regex_rev = re.findall(r'(?<=rev:)\d+',line)
                                
                if regex_emptyline or not regex_sid:
                        pass
                
                else:
                     
                        if regex_Hashes:
                
                                rule_split = line.split(" ")
                                rule_status = "Disabled"
                                sid_int = int(regex_sid[0])
                                rev_int = int(regex_rev[0])
                                action_str = str(rule_split[1])
                                protocol_str = str(rule_split[2])
                                src_network_str = str(rule_split[3])
                                src_pt_str = str(rule_split[4])
                                dst_network_str = str(rule_split[6])
                                dst_network_pt_str = str(rule_split[7])
                                signature = str(line)


                                rule_list.append( Rule(rule_status, sid_int, rev_int, action_str, protocol_str, src_network_str, src_pt_str, dst_network_str, dst_network_pt_str, signature))             

                        else: 

                                rule_split = line.split(" ")
                                rule_status = "Enabled"     
                                sid_int = int(regex_sid[0])
                                rev_int = int(regex_rev[0])
                                action_str = str(rule_split[0])
                                protocol_str = str(rule_split[1])
                                src_network_str = str(rule_split[2])
                                src_pt_str = str(rule_split[3])
                                dst_network_str = str(rule_split[5])
                                dst_network_pt_str = str(rule_split[6])
                                signature = str(line)

                               

                                rule_list.append( Rule(rule_status, sid_int, rev_int, action_str, protocol_str, src_network_str, src_pt_str, dst_network_str, dst_network_pt_str, signature))
        print("rule complete")  

    def export_ruleset(self):
        global outputfile

        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()
        sql_cursor.execute("SELECT rule_body FROM rules.rulesets WHERE rulestatus ='Enabled'")

        Exportfile = open(outputfile, 'a')
        for x in sql_cursor:
                Exportfile.write(str(x[0]))


# This is the function to import rulesets. 

    def inport_ruleset(self):
        global inputfile

        Rule.get_sidrev_from_database(self)
        Rule.create_list(self)
        Rule.compare_database_to_rulelist(self)
        Rule.transfer_to_database(self)
        
        MyGui.initial_load_data(self)
        MyGui.show_import_success_box(self)

        

#This is the datatable that is used to display the SNORT rule data. This class is used in the mainwindow below.
class dataTable(QTableWidget):
    def __init__(self):
        super().__init__()

        self.show()

#This is the mainwindow for the program and has all components detailing this. 

class MyGui(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SNORT Database application")
        self.setMinimumSize(1200, 600)
        self.showMaximized()

#This is the configurations and specifications for the datatable.

        self.table_widget = dataTable()
        self.setCentralWidget(self.table_widget)
        self.table_widget.setColumnCount(11)
        self.table_widget.setRowCount(6000)
        self.table_widget.setHorizontalHeaderLabels(('ID', 'Rule status', 'Signature ID', 'Revision', 'Action', 'Protocol','Source Network', 'Source Port','Destination Network', 'Destination Port','Rule Body'))
        self.table_widget.setColumnWidth(7,120)
        self.table_widget.setColumnWidth(10,2000)
        self.table_widget.verticalHeader().setVisible(False)

#This intinates the functions in this class.  
        
        self.create_menu()
        self.Statusbar()
        self.initial_load_data()
        #Rule.export_ruleset(self) 
        #Rule.inport_ruleset(self)
        Rule.check_if_table_empty(self)
        
        
#This displays the about box. 
    def show_about_box(self):
        msg = QMessageBox()
        msg.setWindowTitle("About SNORT Database Application")
        msg.setText("SNORT Database Application created by Gerwyn George 2020.")
        x = msg.exec_()


#These need to be completed and refined. 
    def show_importfile_box(self):
        global inputfile
        
        filebox = QFileDialog
        inputfile = filebox.getOpenFileName(self,caption="Import Ruleset", filter="Text files(*.txt);; Rules files(*.rules)")
        
        

        if inputfile:
                inputfile =str(inputfile[0])
                Rule.inport_ruleset(self)

#This works, needs refinement, error checking
    def show_exportfile_box(self):
        global outputfile

        filebox = QFileDialog
        outputfile = filebox.getSaveFileName(self,caption="Export Ruleset", filter="Text files(*.txt);; Rules files(*.rules)")
        if outputfile:
                outputfile = str(outputfile[0])
                Rule.export_ruleset(self)

    def show_import_success_box(self):
        global total_import_counter
        global ignore_import_counter
        global new_import_counter
        global enabled_import_counter 
        global disabled_import_counter 
        
        msg = QMessageBox(QMessageBox.Information, "Import Results", "Attempted to import %s rules. \n%s rules already in database and have not been added.\n%s new rules have been added to database. \n%s of these rules are in an enabled state.\n%s of these rules are in a disabled state." % (total_import_counter,ignore_import_counter,new_import_counter,enabled_import_counter,disabled_import_counter), QMessageBox.Ok)
        x = msg.exec_()

#This specifies the top menu bar and its configuration. 

    def create_menu(self):
        mainMenu = self.menuBar()
        fileMenu = mainMenu.addMenu("File")
        ruleMenu = mainMenu.addMenu("Rule")
        configMenu = mainMenu.addMenu("Config")
        helpMenu = mainMenu.addMenu("Help")

#This is for the rule menu.
        importruleaction = QAction("Import Ruleset", self)
        importruleaction.triggered.connect(self.show_importfile_box)
        
        exportruleaction = QAction("Export Ruleset", self)
        exportruleaction.triggered.connect(self.show_exportfile_box)
        
        ruleMenu.addAction(importruleaction)
        ruleMenu.addAction(exportruleaction)

#This is for the configure menu.
        serversettingsruleaction = QAction("Server Configuration", self)
        testconnectionruleaction = QAction("Test server connection",self)

        configMenu.addAction(serversettingsruleaction)
        configMenu.addAction(testconnectionruleaction)

#This is for the options which drop down for the Help menu.
        howtoaction = QAction("How to", self)

        aboutaction = QAction("About", self)
        aboutaction.triggered.connect(self.show_about_box)

        helpMenu.addAction(howtoaction)
        helpMenu.addAction(aboutaction)

#This specifies the configuration for the statusbar.

    def Statusbar(self):
        status = QStatusBar()
        status.showMessage("Ready")
        self.setStatusBar(status)

#This function creates a database if one is not found on loadup.

    def create_initial_database(self):
        try:
                connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
      
                if connection.is_connected():
                        sql_cursor = connection.cursor()
                        sql_cursor.execute("CREATE DATABASE rules")
                        sql_cursor.execute("CREATE TABLE rules.rulesets (id INT AUTO_INCREMENT PRIMARY KEY, rulestatus VARCHAR(255), sid VARCHAR(255), rev VARCHAR(255), action VARCHAR(255), protocol VARCHAR(255), src_network VARCHAR(255), src_port VARCHAR(255), dst_network VARCHAR(255), dst_port VARCHAR(255), rule_body TEXT(65535))") 
                        connection.close
                        print("Database has been created")
            
        except mysql.connector.Error as error_text:
        
                if error_text.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                        print("Can not connect to database.")     

                else:
                        print(error_text)


#This function loads the intial data into the table from the database and displays it.  

    def initial_load_data(self):
        
        try:
                mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                passwd="Forgotten07",
                database="rules")

                if mydb.is_connected():
                        mycursor=mydb.cursor()
                        mycursor.execute("SELECT * FROM rules.rulesets")
                        result = mycursor.fetchall()

                        for row_number, data_row in enumerate (result):
                                for col_number, item in enumerate (data_row):
                                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item))) 
                        
                        mydb.close()

                        
        except mysql.connector.Error as error_text:
                if error_text.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                        print("Can not connect to database.")
            
                elif error_text.errno == errorcode.ER_BAD_DB_ERROR:
                        print("Database does not exist.")
                        self.create_initial_database()
                        

                else:
                        print(error_text)


app = QApplication(sys.argv)
mygui = MyGui()
sys.exit(app.exec_())
