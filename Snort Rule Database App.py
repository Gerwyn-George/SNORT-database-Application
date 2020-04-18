import sys
import re
from time import sleep

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
from PySide2.QtWidgets import QFormLayout
from PySide2.QtWidgets import QLineEdit
from PySide2.QtWidgets import QLabel
from PySide2.QtWidgets import QGridLayout
from PySide2.QtWidgets import QPushButton
from PySide2.QtWidgets import QDockWidget 
from PySide2.QtWidgets import QComboBox

from PySide2.QtCore import Qt



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

class database():

    hostname = "127.0.0.1" 
    user = "root"
    password = "Forgotten07"
    database_name = "rules"

    def __init__(self):

             #snort-database-application.c5acoc6h2uoc.eu-west-2.rds.amazonaws.com"

        self.database_status = "Ready"

    def connect_to_database(self):
        try:
                conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
                if conn.is_connected():
                    cur = conn.cursor()
                 
                    print("connected")

                    #This is the way you can display guis from the mygui class. 
                    #MyGui.show_database_config_box(self) 
                       
        except mysql.connector.Error as error_text:

                if error_text.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                        print("Can not connect to database.") 
                           

                elif error_text.errno == errorcode.ER_BAD_DB_ERROR:
                        MyGui.Show_no_database_found_box(self)
                                
                else:
                        print(error_text)

    def disconnect_from_database(self):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        conn.close() 
    

    def get_data(self,query):
        self.connect_to_database()
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        cur = conn.cursor() 
        cur.execute(query)
        query_result = cur.fetchall()
        self.disconnect_from_database() 
      
        #print(query_result)
        return  query_result 
    
    def execute_query(self,query):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        cur = conn.cursor()
        cur.execute(query)
        self.disconnect_from_database() 
    
    def create_intial_database(self):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        cur = conn.cursor()
        cur.execute("CREATE DATABASE rules;")
        cur.execute("CREATE TABLE rules.rulesets (id INT AUTO_INCREMENT PRIMARY KEY, rulestatus VARCHAR(255), sid VARCHAR(255), rev VARCHAR(255), action VARCHAR(255), protocol VARCHAR(255), src_network VARCHAR(255), src_port VARCHAR(255), dst_network VARCHAR(255), dst_port VARCHAR(255), rule_body TEXT(65535))")
        self.disconnect_from_database() 
        MyGui.Show_database_created_box(self) 



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
    

    def transfer_to_database(self):

        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()

        for rule in rule_list:

                if rule.exists_in_db == True:
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

    def create_list(self):
        global inputfile

        try:

                Importfile = open(inputfile, 'r')

        except FileNotFoundError:
        
                pass 
        else: 
        
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
                

    def export_ruleset(self):
        global outputfile

        connection = mysql.connector.connect(host="127.0.0.1",user="root",passwd="Forgotten07")
        sql_cursor = connection.cursor()
        sql_cursor.execute("SELECT rule_body FROM rules.rulesets WHERE rulestatus ='Enabled'")

        Exportfile = open(outputfile, 'a')
        for x in sql_cursor:
                Exportfile.write(str(x[0]))

        MyGui.show_export_success_box(self)


# This is the function to import rulesets. 

    def inport_ruleset(self):
        global inputfile

        Rule.get_sidrev_from_database(self)
        Rule.create_list(self)
        Rule.compare_database_to_rulelist(self)
        Rule.transfer_to_database(self)

        Rule.initial_load_data(self)
        MyGui.show_import_success_box(self)
        rule_list.clear()

class dataTable(QTableWidget):
    def __init__(self):
        super().__init__()
         
        self.show()


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
        self.table_widget.setRowCount(4000)
        self.table_widget.setHorizontalHeaderLabels(('ID', 'Rule status', 'Signature ID', 'Revision', 'Action', 'Protocol','Source Network', 'Source Port','Destination Network', 'Destination Port','Rule Body'))
        self.table_widget.setColumnWidth(8,120)
        self.table_widget.setColumnWidth(10,2000)
        self.table_widget.verticalHeader().setVisible(False)



        self.first_title_combobox = QComboBox()
        self.first_title_combobox.addItem("")
        self.first_title_combobox.addItem("Rule Status")
        self.first_title_combobox.addItem("Signature ID")
        self.first_title_combobox.addItem("Revison")
        self.first_title_combobox.addItem("Action")
        self.first_title_combobox.addItem("Protocol")
        self.first_title_combobox.addItem("Source Network")
        self.first_title_combobox.addItem("Source Port")
        self.first_title_combobox.addItem("Destination Network")
        self.first_title_combobox.addItem("Destination Port")
        self.first_title_combobox.addItem("Rule Body")

        self.second_title_combobox = QComboBox()
        self.second_title_combobox.addItem("")
        self.second_title_combobox.addItem("Rule Status")
        self.second_title_combobox.addItem("Signature ID")
        self.second_title_combobox.addItem("Revision")
        self.second_title_combobox.addItem("Action")
        self.second_title_combobox.addItem("Protocol")
        self.second_title_combobox.addItem("Source Network")
        self.second_title_combobox.addItem("Source Port")
        self.second_title_combobox.addItem("Destination Network")
        self.second_title_combobox.addItem("Desination Port")
        self.second_title_combobox.addItem("Rule Body")

        self.third_title_combobox = QComboBox()
        self.third_title_combobox.addItem("")
        self.third_title_combobox.addItem("Rule Status")
        self.third_title_combobox.addItem("Signature ID")
        self.third_title_combobox.addItem("Revision")
        self.third_title_combobox.addItem("Action")
        self.third_title_combobox.addItem("Protocol")
        self.third_title_combobox.addItem("Source Network")
        self.third_title_combobox.addItem("Source Port")
        self.third_title_combobox.addItem("Destination Network")
        self.third_title_combobox.addItem("Destination Port")
        self.third_title_combobox.addItem("Rule Body") 

        self.fouth_title_combobox = QComboBox()
        self.fouth_title_combobox.addItem("") 
        self.fouth_title_combobox.addItem("Rule Status")
        self.fouth_title_combobox.addItem("Signature ID")
        self.fouth_title_combobox.addItem("Revision")
        self.fouth_title_combobox.addItem("Action")
        self.fouth_title_combobox.addItem("Protocol")
        self.fouth_title_combobox.addItem("Source Network")
        self.fouth_title_combobox.addItem("Source Port")
        self.fouth_title_combobox.addItem("Destination Network")
        self.fouth_title_combobox.addItem("Destination Port")
        self.fouth_title_combobox.addItem("Rule Body")

        self.fifth_title_combobox = QComboBox()
        self.fifth_title_combobox.addItem("")
        self.fifth_title_combobox.addItem("Rule Status")
        self.fifth_title_combobox.addItem("Signature ID")
        self.fifth_title_combobox.addItem("Revision")
        self.fifth_title_combobox.addItem("Action")
        self.fifth_title_combobox.addItem("Protocol")
        self.fifth_title_combobox.addItem("Source Network")
        self.fifth_title_combobox.addItem("Source Port")
        self.fifth_title_combobox.addItem("Destination Network")
        self.fifth_title_combobox.addItem("Destination Port")
        self.fifth_title_combobox.addItem("Rule Body") 


        self.first_conditional_combobox = QComboBox()
        self.first_conditional_combobox.addItem("")
        self.first_conditional_combobox.addItem("Contains")
        self.first_conditional_combobox.addItem("Does Not Contain")
        self.first_conditional_combobox.addItem("Is")
        self.first_conditional_combobox.addItem("Is not")

        self.second_conditional_combobox = QComboBox() 
        self.second_conditional_combobox.addItem("")
        self.second_conditional_combobox.addItem("Contains")
        self.second_conditional_combobox.addItem("Does Not Contain")
        self.second_conditional_combobox.addItem("Is")
        self.second_conditional_combobox.addItem("Is not")

        self.third_conditional_combobox = QComboBox()
        self.third_conditional_combobox.addItem("")
        self.third_conditional_combobox.addItem("Contains")
        self.third_conditional_combobox.addItem("Does Not Contain")
        self.third_conditional_combobox.addItem("Is")
        self.third_conditional_combobox.addItem("Is not")

        self.fourth_conditional_combobox = QComboBox()
        self.fourth_conditional_combobox.addItem("")
        self.fourth_conditional_combobox.addItem("Contains")
        self.fourth_conditional_combobox.addItem("Does Not Contain")
        self.fourth_conditional_combobox.addItem("Is")
        self.fourth_conditional_combobox.addItem("Is not")

        self.fifth_conditional_combobox = QComboBox()
        self.fifth_conditional_combobox.addItem("")
        self.fifth_conditional_combobox.addItem("Contains")
        self.fifth_conditional_combobox.addItem("Does Not Contain")
        self.fifth_conditional_combobox.addItem("Is")
        self.fifth_conditional_combobox.addItem("Is not")

        self.first_search_input = QLineEdit()
        self.second_search_input = QLineEdit()
        self.third_search_input = QLineEdit()
        self.fourth_search_input = QLineEdit()
        self.fifth_search_input = QLineEdit() 

        self.first_operator_combobox = QComboBox()
        self.first_operator_combobox.addItem("")
        self.first_operator_combobox.addItem("AND")
        self.first_operator_combobox.addItem("OR")

        self.second_operator_combobox = QComboBox()
        self.second_operator_combobox.addItem("")
        self.second_operator_combobox.addItem("AND")
        self.second_operator_combobox.addItem("OR")

        self.third_operator_combobox = QComboBox()
        self.third_operator_combobox.addItem("")
        self.third_operator_combobox.addItem("AND")
        self.third_operator_combobox.addItem("OR")

        self.fourth_operator_combobox = QComboBox()
        self.fourth_operator_combobox.addItem("")
        self.fourth_operator_combobox.addItem("AND")
        self.fourth_operator_combobox.addItem("OR")

        self.fifth_operator_combobox = QComboBox()
        self.fifth_operator_combobox.addItem("")
        self.fifth_operator_combobox.addItem("AND")
        self.fifth_operator_combobox.addItem("OR")

        self.search_filter_button = QPushButton("Filter")
        self.search_reset_button = QPushButton("Reset")
        self.search_reset_button.clicked.connect(self.display_all_rules)


        self.search_engine = QWidget()

        search_engine_layout = QGridLayout()
        search_engine_layout.addWidget(self.first_title_combobox,0,0,) 
        search_engine_layout.addWidget(self.first_conditional_combobox,0,1)
        search_engine_layout.addWidget(self.first_search_input,0,2)
        search_engine_layout.addWidget(self.first_operator_combobox,0,3,1,2)

        search_engine_layout.addWidget(self.second_title_combobox,1,0,)
        search_engine_layout.addWidget(self.second_conditional_combobox,1,1)
        search_engine_layout.addWidget(self.second_search_input,1,2,)
        search_engine_layout.addWidget(self.second_operator_combobox,1,3,1,2)
        

        search_engine_layout.addWidget(self.third_title_combobox,2,0,)
        search_engine_layout.addWidget(self.third_conditional_combobox,2,1)
        search_engine_layout.addWidget(self.third_search_input,2,2)
        search_engine_layout.addWidget(self.third_operator_combobox,2,3,1,2)

        search_engine_layout.addWidget(self.fouth_title_combobox,3,0,)
        search_engine_layout.addWidget(self.fourth_conditional_combobox,3,1)
        search_engine_layout.addWidget(self.fourth_search_input,3,2)
        search_engine_layout.addWidget(self.fourth_operator_combobox,3,3,1,2)

        search_engine_layout.addWidget(self.fifth_title_combobox,4,0,)
        search_engine_layout.addWidget(self.fifth_conditional_combobox,4,1)
        search_engine_layout.addWidget(self.fifth_search_input,4,2)
        search_engine_layout.addWidget(self.fifth_operator_combobox,4,3,1,2)

        search_engine_layout.addWidget(self.search_filter_button,5,4)
        search_engine_layout.addWidget(self.search_reset_button,5,3)

        self.search_engine.setLayout(search_engine_layout)
        self.search_engine.show()



#This is for the search engine element 

        self.search_widget = QDockWidget("Search Engine",self)
        self.search_widget.setFloating(False)
        self.search_widget.setWidget(self.search_engine)
        self.search_widget.setAllowedAreas(Qt.TopDockWidgetArea | Qt.BottomDockWidgetArea)
        self.search_widget.setFeatures(QDockWidget.DockWidgetMovable)
        self.addDockWidget(Qt.TopDockWidgetArea, self.search_widget) 


        
        

#This intinates the functions in this class.  
        
        self.create_menu()
        self.Statusbar()
        self.display_all_rules() 
        
    def show_database_config_box(self):

        hostname = str(database().hostname)
        user = str(database().user)
        database_name = str(database().database_name)

        msg = QMessageBox(QMessageBox.Information, "Database Configuration settings", "Currently using the following settings.\n\nServer IP address/hostname: %s\nUsername: %s\nDatabase: %s" % (hostname,user,database_name), QMessageBox.Ok)
        x = msg.exec_()

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

    def show_export_success_box(self):
        msg = QMessageBox(QMessageBox.Information, "Ruleset Creation Successful", "Ruleset successfully created.",QMessageBox.Ok)
        x = msg.exec_()

    def Show_no_database_found_box(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Database not found")
        msg.setText("Database not found. Create database with default settings?")
        response = msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        ButtonYes = msg.button(QMessageBox.Yes)
        ButtonNo = msg.button(QMessageBox.No)
        x = msg.exec_() 

        if msg.clickedButton() == ButtonYes:
                database().create_intial_database() 
        else:
                pass 

    def Show_database_created_box(self):
        msg = QMessageBox(QMessageBox.Information, "Database created", "Initial database created successfully.", QMessageBox.Ok)
        x = msg.exec_()

    

    def modify_network_config(self):
       
       new_host = str(self.ammend_hostname.text())
       new_user = str(self.ammend_user.text())
       new_database_name = str(self.ammend_database.text())
       new_password = str(self.ammend_password.text())
       
       database().__class__.hostname = new_host
       database().__class__.user = new_user 
       database().__class__.database_name = new_database_name 
       database().__class__.password = new_password
       self.Config_window.close() 

    def close_network_config(self):
        self.Config_window.close()

    def Configure_database_box(self):
        self.Config_window = QWidget() 
        self.Config_window.setWindowTitle("Configure Database")

        self.okaybutton = QPushButton("OK")
        self.okaybutton.clicked.connect(self.modify_network_config)

        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(self.close_network_config)
        

        self.ammend_hostname = QLineEdit() 
        self.ammend_hostname.setText(database().hostname) 
  
        self.ammend_password = QLineEdit()
        self.ammend_password.setText(database().password)
        self.ammend_password.setEchoMode(QLineEdit.EchoMode.Password)

        self.ammend_user = QLineEdit()
        self.ammend_user.setText(database().user)

        self.ammend_database = QLineEdit()
        self.ammend_database.setText(database().database_name)

        layout = QGridLayout() 
        layout.addWidget(QLabel('Input database configuration settings'),0,0,)

        layout.addWidget(QLabel('IP address / Hostname: '),1,0)
        layout.addWidget(self.ammend_hostname,1,1,1,3)
       
        layout.addWidget(QLabel('Username: '),2,0)
        layout.addWidget(self.ammend_user,2,1,1,3)

        layout.addWidget(QLabel('Password: '),3,0)
        layout.addWidget(self.ammend_password,3,1,1,3)

        layout.addWidget(QLabel('Database Name: '),4,0)
        layout.addWidget(self.ammend_database,4,1,1,3)

        layout.addWidget(self.cancelButton,5,3)
        layout.addWidget(self.okaybutton,5,2)

        self.Config_window.setLayout(layout)
        self.Config_window.show() 
        
#This specifies the top menu bar and its configuration. 

    def create_menu(self):
        mainMenu = self.menuBar()
        fileMenu = mainMenu.addMenu("File")
        ruleMenu = mainMenu.addMenu("Rule")
        viewMenu = mainMenu.addMenu("View")
        configMenu = mainMenu.addMenu("Config")
        helpMenu = mainMenu.addMenu("Help")

#This is for the rule menu.
        importruleaction = QAction("Import Ruleset", self)
        importruleaction.triggered.connect(self.show_importfile_box)
        
        exportruleaction = QAction("Export Ruleset", self)
        exportruleaction.triggered.connect(self.show_exportfile_box)
        
        ruleMenu.addAction(importruleaction)
        ruleMenu.addAction(exportruleaction)

#This is for the view menu.
        displayallrulesaction = QAction("All rules",self)
        displayallrulesaction.triggered.connect(self.display_all_rules)
        
        displayenabledrulesaction = QAction("Enabled rules",self)
        displayenabledrulesaction.triggered.connect(self.display_enabled_rules)

        displaydisabledrulesaction = QAction("Disabled rules",self)
        displaydisabledrulesaction.triggered.connect(self.display_disabled_rules)
        
        viewMenu.addAction(displayallrulesaction)
        viewMenu.addAction(displayenabledrulesaction)
        viewMenu.addAction(displaydisabledrulesaction)
        
#This is for the configure menu.
        display_serversettingsruleaction = QAction("Display Database connection settings", self)
        display_serversettingsruleaction.triggered.connect(self.show_database_config_box)

        modify_serversettingsruleaction = QAction("Modify Database connection settings",self)
        modify_serversettingsruleaction.triggered.connect(self.Configure_database_box)
        

        testconnectionruleaction = QAction("Test server connection",self)

        configMenu.addAction(modify_serversettingsruleaction)
        configMenu.addAction(display_serversettingsruleaction)
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
        status.showMessage(database().database_status)
        self.setStatusBar(status)


    def display_all_rules(self):

            self.table_widget.clearContents()
         

            result = database().get_data("SELECT * FROM rules.rulesets")
        
            for row_number, data_row in enumerate (result):
               
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item))) 

    
    def display_enabled_rules(self):
      
            self.table_widget.clearContents()
           
            result = database().get_data("SELECT * FROM rules.rulesets WHERE rulestatus ='Enabled'")

            for row_number, data_row in enumerate (result):
               
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item)))
    
    def display_disabled_rules(self):
      
            self.table_widget.clearContents()

            result = database().get_data("SELECT * FROM rules.rulesets WHERE rulestatus ='Disabled'")

            for row_number, data_row in enumerate (result):
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item)))

    def display_filtered_rules(self):

           self.table_widget.clearContents()

           final_Query = "" 

    


#This function loads the intial data into the table from the database and displays it.  

app = QApplication(sys.argv)
mygui = MyGui()
 
sys.exit(app.exec_())
