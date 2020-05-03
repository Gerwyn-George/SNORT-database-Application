import sys
import re
from threading import Thread
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
from PySide2.QtWidgets import QTextEdit
from PySide2.QtWidgets import QCompleter


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
inputfile = ""
outputfile = ""

#This class specifies all parts of the snort rule. This allows for data to be stored in memory before transfering to database.

class database():

    hostname = "snort-database-application-db.c5acoc6h2uoc.eu-west-2.rds.amazonaws.com"
    user = "admin"
    password = "Forgotten07"
    database_name = "rules"

    Last_Query = ""

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
        cur = conn.cursor(prepared=True) 
        cur.execute(query) 
        query_result = cur.fetchall()
        self.disconnect_from_database() 
      
        return  query_result 
    
    def execute_query(self,query):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        cur = conn.cursor()
        cur.execute(query)
        conn.commit()
        
        self.disconnect_from_database() 
   
    def execute_query_many(self,query,values):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password,database=self.database_name)
        cur = conn.cursor()
        cur.executemany(query,values)
        conn.commit()

        self.disconnect_from_database()


    def create_intial_database(self):
        conn = mysql.connector.connect(host=self.hostname,user=self.user,passwd=self.password)
        cur = conn.cursor()
        cur.execute("CREATE DATABASE rules;")
        cur.execute("CREATE TABLE rules.rulesets (id INT AUTO_INCREMENT PRIMARY KEY, rulestatus VARCHAR(255), sid VARCHAR(255), rev VARCHAR(255), action VARCHAR(255), protocol VARCHAR(255), src_network VARCHAR(255), src_port VARCHAR(255), dst_network VARCHAR(255), dst_port VARCHAR(255), rule_body TEXT(65535))")
        self.disconnect_from_database() 
        MyGui.Show_database_created_box(self) 

    def collect_all_sids(self):
        collect = self.get_data("SELECT sid FROM rules.rulesets")
        result = []

        for i in collect: 
                result.append(i[0])
        return result 
        


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



    def import_data_into_db(self):
 
        new_rule_list =[] 

        insert_qry = "INSERT INTO rules.rulesets (rulestatus, sid, rev, action, protocol, src_network, src_port, dst_network, dst_port, rule_body) VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s)"

        for rule in rule_list:

                if rule.exists_in_db == True:
                        pass

                else:
                
                        values = (rule.rule_status, rule.sid, rule.rev, rule.action, rule.protocol, rule.src_network, rule.src_pt, rule.dst_network, rule.dst_pt,rule.rule_body)
                        new_rule_list.append(values)
                        
        database().execute_query_many(insert_qry,new_rule_list)                  


    def transfer_to_database(self):
            background_task = Thread(target=Rule().import_data_into_db())
            background_task.daemon  = True
            background_task.start()



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

        sid_list = []
        rev_list = []
        
        result = database().get_data("SELECT sid,rev FROM rules.rulesets")
     
        for x in result:

                sid_list.append(x[0])
                rev_list.append(x[1])
        
        database().disconnect_from_database() 

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
        
        query = database().Last_Query
        print(query)

        result = database().get_data(query)

        Exportfile = open(outputfile, 'a')
        for x in result:
                Exportfile.write(str(x[10]))

        MyGui.show_export_success_box(self)


# This is the function to import rulesets. 

    def inport_ruleset(self):
        global inputfile

        Rule.get_sidrev_from_database(self)
        Rule.create_list(self)
        Rule.compare_database_to_rulelist(self)
        Rule.transfer_to_database(self)

        MyGui.display_all_rules(self)
        MyGui.show_import_success_box(self)
        rule_list.clear()

#This is all the functions for the search engine. 
class search():
    
    Queryheader_1 = ""
    Queryconditional_1 = ""
    Querysearchinput_1 = ""
    Queryoperational_1 = ""

    Queryheader_2 = ""
    Queryconditional_2 = ""
    Querysearchinput_2 = ""
    Queryoperational_2 = ""

    Queryheader_3 = ""
    Queryconditional_3 = ""
    Querysearchinput_3 = ""
    Queryoperational_3 = ""

    Queryheader_4 = ""
    Queryconditional_4 = ""
    Querysearchinput_4 = ""
    Queryoperational_4 = ""

    Queryheader_5 = ""
    Queryconditional_5 = ""
    Querysearchinput_5 = ""
    Queryoperational_5 = ""




    def clear_query_input(self):
        Queryheader_1 = ""
        Queryconditional_1 = ""
        Querysearchinput_1 = ""
        Queryoperational_1 = ""

        Queryheader_2 = ""
        Queryconditional_2 = ""
        Querysearchinput_2 = ""
        Queryoperational_2 = ""

        Queryheader_3 = ""
        Queryconditional_3 = ""
        Querysearchinput_3 = ""
        Queryoperational_3 = ""

        Queryheader_4 = ""
        Queryconditional_4 = ""
        Querysearchinput_4 = ""
        Queryoperational_4 = ""

        Queryheader_5 = ""
        Queryconditional_5 = ""
        Querysearchinput_5 = ""
        Queryoperational_5 = ""
        

    def create_query_line(self):
        
        header1 = ""
        header2 = ""
        header3 = ""
        header4 = ""
        header5 = ""

        Total_Query =""
         
        header1 = self.Queryheader_1
        conditional1 = self.Queryconditional_1
        input1 = self.Querysearchinput_1
        operator1 = self.Queryoperational_1

        header2 = self.Queryheader_2
        conditional2 = self.Queryconditional_2
        input2 = self.Querysearchinput_2
        operator2 = self.Queryoperational_2

        header3 = self.Queryheader_3
        conditional3 = self.Queryconditional_3
        input3 = self.Querysearchinput_3
        operator3 = self.Queryoperational_3

        header4 = self.Queryheader_4
        conditional4 = self.Queryconditional_4
        input4 = self.Querysearchinput_4
        operator4 = self.Queryoperational_4

        header5 = self.Queryheader_5 
        conditional5 = self.Queryconditional_5 
        input5 = self.Querysearchinput_5

        if header1 == "Rule Status":
                header1 = "rulestatus"
                
        if header1 == "Signature ID":
                header1 = "sid"
                
        if header1 == "Revison":
                header1 = "rev"
                
        if header1 == "Action":
                header1 = "action"
                
        if header1 == "Protocol":
                header1 = "protocol"
                
        if header1 == "Source Network":
                header1 = "src_network"
                
        if header1 == "Source Port":
                header1 = "src_port"
                
        if header1 == "Destination Network":
                header1 = "dst_network"
                
        if header1 == "Destination Port":
                header1 = "dst_port"
                
        if header1 == "Rule Body":
                header1 = "rule_body"
                
        
        if header2 == "Rule Status":
                header2 = "rulestatus"
                
        if header2 == "Signature ID":
                header2 = "sid"
                
        if header2 == "Revison":
                header2 = "rev"
                
        if header2 == "Action":
                header2 = "action"
                
        if header2 == "Protocol":
                header2 = "protocol"
                
        if header2 == "Source Network":
                header2 = "src_network"
                
        if header2 == "Source Port":
                header2 = "src_port"
                
        if header2 == "Destination Network":
                header2 = "dst_network"
                
        if header2 == "Destination Port":
                header2 = "dst_port"
                
        if header2 == "Rule Body":
                header2 = "rule_body"
                

        if header3 == "Rule Status":
                header3 = "rulestatus"
                
        if header3 == "Signature ID":
                header3 = "sid"
                
        if header3 == "Revison":
                header3 = "rev"
                
        if header3 == "Action":
                header3 = "action"
                
        if header3 == "Protocol":
                header3 = "protocol"
                
        if header3 == "Source Network":
                header3 = "src_network"
                
        if header3 == "Source Port":
                header3 = "src_port"
                
        if header3 == "Destination Network":
                header3 = "dst_network"
                
        if header3 == "Destination Port":
                header3 = "dst_port"
                
        if header3 == "Rule Body":
                header3 = "rule_body"
                
				
        if header4 == "Rule Status":
                header4 = "rulestatus"
                
        if header4 == "Signature ID":
                header4 = "sid"
                
        if header4 == "Revison":
                header4 = "rev"
                
        if header4 == "Action":
                header4 = "action"
                
        if header4 == "Protocol":
                header4 = "protocol"
                
        if header4 == "Source Network":
                header4 = "src_network"
                
        if header4 == "Source Port":
                header4 = "src_port"
                
        if header4 == "Destination Network":
                header4 = "dst_network"
                
        if header4 == "Destination Port":
                header4 = "dst_port"
                
        if header4 == "Rule Body":
                header4 = "rule_body"
                
				
        if header5 == "Rule Status":
                header5 = "rulestatus"
        
        if header5 == "Signature ID":
                header5 = "sid"
        
        if header5 == "Revison":
                header5 = "rev"
        
        if header5 == "Action":
                header5 = "action"
        
        if header5 == "Protocol":
                header5 = "protocol"
        
        if header5 == "Source Network":
                header5 = "src_network"
               
        if header5 == "Source Port":
                header5 = "src_port"
                
        if header5 == "Destination Network":
                header5 = "dst_network"
               
        if header5 == "Destination Port":
                header5 = "dst_port"
                
        if header5 == "Rule Body":
                header5 = "rule_body"
                


#Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body 

        Query_AND_1 =""
        Query_AND_2 =""
        Query_AND_3 =""
        Query_AND_4 =""

        Query_OR_1 =""
        Query_OR_2 =""
        Query_OR_3 =""
        Query_OR_4 =""
                 
        if header1 is "sid":
                Total_Query = "SELECT * FROM rules.rulesets WHERE " + header1 + " " + conditional1+ " " + input1 
        
        elif header1 is "rev":
                Total_Query = "SELECT * FROM rules.rulesets WHERE " + header1 + " " + conditional1+ " " + input1 
                   
        else:
                Total_Query = "SELECT * FROM rules.rulesets WHERE " + header1 + " " + conditional1+ " '" + input1 + "'"
                
        
        
        if operator1 == "AND":

                if header2 == "sid":
                        Query_AND_1 = " AND " + header2 +" " +conditional2 + " " + input2

                elif header2 == "rev":
                        Query_AND_1 = " AND " + header2 +" " +conditional2 + " " + input2

                else:
                        Query_AND_1 = " AND " + header2 +" " +conditional2 + " '" + input2 + "'"
        
        if operator2 == "AND":

                if header3 == "sid":
                        Query_AND_2 = " AND " + header3 +" " +conditional3 + " " + input3

                elif header3 == "rev":
                        Query_AND_2 = " AND " + header3 +" " +conditional3 + " " + input3

                else:
                        Query_AND_2 = " AND " + header3 +" " +conditional3 + " '" + input3 + "'"        
        
        if operator3 == "AND":
                
                if header4 == "sid":
                        Query_AND_3 = " AND " + header4 +" " +conditional4 + " " + input4

                elif header4 == "rev":
                        Query_AND_3 = " AND " + header4 +" " +conditional4 + " " + input4

                else:
                        Query_AND_3 = " AND " + header4 +" " +conditional4 + " '" + input4 + "'"
        
        if operator4 == "AND":
               

                if header5 == "sid":
                        Query_AND_4 = " AND " + header5 +" " +conditional5 + " " + input5

                elif header5 == "rev":
                        Query_AND_4 = " AND " + header5 +" " +conditional5 + " " + input5

                else:
                        Query_AND_4 = " AND " + header5 +" " +conditional5 + " '" + input5 + "'"



        if operator1 == "OR":

                if header1 == "sid":
                        Query_OR_1 = " OR " + header2 +" " +conditional2 + " " + input2
                
                elif header1 == "rev":
                        Query_OR_1 = " OR " + header2 +" " +conditional2 + " " + input2 
                
                else:
                        Query_OR_1 = " OR " + header2 +" " +conditional2 + " '" + input2 + "'"     
        
        if operator2 == "OR":
                
                if header3 == "sid":
                        Query_OR_2 = " OR " + header3 +" " +conditional3 + " " + input3
                
                elif header3 == "rev":
                        Query_OR_2 = " OR " + header3 +" " +conditional3 + " " + input3 
                
                else:
                        Query_OR_2 = " OR " + header3 +" " +conditional3 + " '" + input3 + "'"
        
        if operator3 == "OR":

                if header4 == "sid":
                        Query_OR_3 = " OR " + header4 +" " +conditional4 + " " + input4
                
                elif header4 == "rev":
                        Query_OR_3 = " OR " + header4 +" " +conditional4 + " " + input4 
                
                else:
                        Query_OR_3 = " OR " + header4 +" " +conditional4 + " '" + input4 + "'"
        
        if operator4 == "OR":

                if header5 == "sid":
                        Query_OR_4 = " OR " + header5 +" " +conditional5 + " " + input5
                
                elif header5 == "rev":
                        Query_OR_4 = " OR " + header5 +" " +conditional5 + " " + input5 
                
                else:
                        Query_OR_4 = " OR " + header5 +" " +conditional5 + " '" + input5 + "'"
        
        
        Total_Query = (Total_Query + Query_AND_1 + Query_AND_2 + Query_AND_3 + Query_AND_4 + Query_OR_1 + Query_OR_2 + Query_OR_3 + Query_OR_4)
        

        return Total_Query

        

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
        
        

#This is the layout for the search engine. 

        self.first_title_combobox = QComboBox()
        self.first_title_combobox.addItems(["","Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body"])

        self.second_title_combobox = QComboBox()
        self.second_title_combobox.addItems(["","Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body"])

        self.third_title_combobox = QComboBox()
        self.third_title_combobox.addItems(["","Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body"])

        self.fouth_title_combobox = QComboBox()
        self.fouth_title_combobox.addItems(["","Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body"])

        self.fifth_title_combobox = QComboBox()
        self.fifth_title_combobox.addItems(["","Rule Status","Signature ID","Revison","Action","Protocol","Source Network","Source Port","Destination Network","Destination Port","Rule Body"])

        self.first_conditional_combobox = QComboBox()
        self.first_conditional_combobox.addItems(["","=","!=","<",">","<=",">="])

        self.second_conditional_combobox = QComboBox() 
        self.second_conditional_combobox.addItems(["","=","!=","<",">","<=",">="])

        self.third_conditional_combobox = QComboBox()
        self.third_conditional_combobox.addItems(["","=","!=","<",">","<=",">="])


        self.fourth_conditional_combobox = QComboBox()
        self.fourth_conditional_combobox.addItems(["","=","!=","<",">","<=",">="])

        self.fifth_conditional_combobox = QComboBox()
        self.fifth_conditional_combobox.addItems(["","=","!=","<",">","<=",">="])


        self.first_search_input = QLineEdit()
        self.second_search_input = QLineEdit()
        self.third_search_input = QLineEdit()
        self.fourth_search_input = QLineEdit()
        self.fifth_search_input = QLineEdit() 

        self.first_operator_combobox = QComboBox()
        self.first_operator_combobox.addItems(["","AND","OR"])
       
        self.second_operator_combobox = QComboBox()
        self.second_operator_combobox.addItems(["","AND","OR"])

        self.third_operator_combobox = QComboBox()
        self.third_operator_combobox.addItems(["","AND","OR"])

        self.fourth_operator_combobox = QComboBox()
        self.fourth_operator_combobox.addItems(["","AND","OR"])

        self.fifth_operator_combobox = QComboBox()
        self.fifth_operator_combobox.addItems(["","AND","OR"])

        self.search_filter_button = QPushButton("Filter")
        
        self.search_filter_button.clicked.connect(self.display_filtered_rules)
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



#This is for the search engine dock element. 

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

    def display_details_in_modify_rule_box(self,query):
        query = query + self.find_signature.text()
       
        result = database().get_data(query) 

        rule_data = []

        for i in result:
                for j in i:
                     rule_data.append(j)
        
        if rule_data[1] == "Enabled":
        
                self.select_rule_status.setCurrentIndex(0)

        if rule_data[1] == "Disabled": 
                self.select_rule_status.setCurrentIndex(1)


        if rule_data[4] == "alert":
                self.select_action.setCurrentIndex(1)
        
        if rule_data[4] == "log":
                self.select_action.setCurrentIndex(2)

        if rule_data[4] == "pass":
                self.select_action.setCurrentIndex(3)

        if rule_data[4] == "activate":
                self.select_action.setCurrentIndex(4)
        
        if rule_data[4] == "dynamic":
                self.select_action.setCurrentIndex(5)

        
        if rule_data[5] == "tcp":
                self.select_protocol.setCurrentIndex(1)
        if rule_data[5] == "udp":
                self.select_protocol.setCurrentIndex(2)
        if rule_data[5] == "icmp":
                self.select_protocol.setCurrentIndex(3)

        self.database_id = rule_data[0]

        self.edit_signature_number.setText(rule_data[2])
        self.edit_rev_number.setText(rule_data[3])

        self.edit_destination_network.setText(rule_data[8])
        self.edit_destination_port.setText(rule_data[9])

        self.edit_source_network.setText(rule_data[6])
        self.edit_source_port.setText(rule_data[7])

        self.rule_edit.setText(rule_data[10])

    def Okay_Modify_rule_box_to_db(self):
        
        source_port = self.edit_source_port.text()
        source_network = self.edit_source_network.text()
        destination_network = self.edit_destination_network.text()
        destination_port = self.edit_destination_port.text() 

        rev_number = self.edit_rev_number.text()
        signature_number = self.edit_signature_number.text() 

        rule_body = self.rule_edit.toPlainText()

        protocol = self.select_protocol.currentText()
        action = self.select_action.currentText()

        rule_status = self.select_rule_status.currentText()

        query = "UPDATE rules.rulesets SET rulestatus = " + "'"+ str(rule_status) +"'"+ "," + " sid = " + "'" + str(signature_number)+ "'" + "," + " rev = " +"'"+ str(rev_number)+"'" + "," + " action = "+"'"+ str(action)+"'" + "," + " protocol = " + "'"+str(protocol)+"'" + "," + " src_network = " + "'"+ str(source_network)+ "'" + "," + " src_port = " + "'" + str(source_port) + "'" + "," + " dst_network = " + "'"+ str(destination_network)+"'"+"," + " dst_port = " + "'"+ str(destination_port)+"'" + " WHERE id = " + str(self.database_id) + ";"
   
        database().execute_query(query)

        regex_rule_body = re.search(r'\(.*?\)', rule_body)

        rule_body=regex_rule_body.group(0)

        signature_number = "sid:" + signature_number + ";"
        rev_number = "rev:" + rev_number + ";"

        rule_body = re.sub(r'(?i)(sid)\:\d+\;',signature_number,rule_body)

        rule_body = re.sub(r'(?i)(rev)\:\d+\;',rev_number,rule_body)

        reconstructed_rule = action + " " + protocol + " " + source_network + " " + source_port + " " + destination_network + " " + destination_port + " " + rule_body
        
        regex_Hashes = re.findall(r'^#',rule_body)

        if rule_status == "Disabled":
                reconstructed_rule = "# " + reconstructed_rule 

        if rule_status == "Enabled":
                pass 
        
        reconstructed_rule = reconstructed_rule.replace("'","''")

        query = "UPDATE rules.rulesets SET rule_body = '"+ reconstructed_rule +"'"+ " WHERE id = " + str(self.database_id) + ";"
       
        database().execute_query(query)

        query = "SELECT * FROM rules.rulesets WHERE sid = "  
        self.display_details_in_modify_rule_box(query)
        self.rule_modify_window.close() 
        

    def Apply_Modify_rule_box_to_db(self):
        
        source_port = self.edit_source_port.text()
        source_network = self.edit_source_network.text()
        destination_network = self.edit_destination_network.text()
        destination_port = self.edit_destination_port.text() 

        rev_number = self.edit_rev_number.text()
        signature_number = self.edit_signature_number.text() 

        rule_body = self.rule_edit.toPlainText()

        protocol = self.select_protocol.currentText()
        action = self.select_action.currentText()

        rule_status = self.select_rule_status.currentText()

        query = "UPDATE rules.rulesets SET rulestatus = " + "'"+ str(rule_status) +"'"+ "," + " sid = " + "'" + str(signature_number)+ "'" + "," + " rev = " +"'"+ str(rev_number)+"'" + "," + " action = "+"'"+ str(action)+"'" + "," + " protocol = " + "'"+str(protocol)+"'" + "," + " src_network = " + "'"+ str(source_network)+ "'" + "," + " src_port = " + "'" + str(source_port) + "'" + "," + " dst_network = " + "'"+ str(destination_network)+"'"+"," + " dst_port = " + "'"+ str(destination_port)+"'" + " WHERE id = " + str(self.database_id) + ";"
   
        database().execute_query(query)

        regex_rule_body = re.search(r'\(.*?\)', rule_body)

        rule_body=regex_rule_body.group(0)

        signature_number = "sid:" + signature_number + ";"
        rev_number = "rev:" + rev_number + ";"

        rule_body = re.sub(r'(?i)(sid)\:\d+\;',signature_number,rule_body)

        rule_body = re.sub(r'(?i)(rev)\:\d+\;',rev_number,rule_body)

        reconstructed_rule = action + " " + protocol + " " + source_network + " " + source_port + " " + destination_network + " " + destination_port + " " + rule_body
        
        regex_Hashes = re.findall(r'^#',rule_body)

        if rule_status == "Disabled":
                reconstructed_rule = "# " + reconstructed_rule 

        if rule_status == "Enabled":
                pass 
        
        reconstructed_rule = reconstructed_rule.replace("'","''")

        query = "UPDATE rules.rulesets SET rule_body = '"+ reconstructed_rule +"'"+ " WHERE id = " + str(self.database_id) + ";"
       
        database().execute_query(query)

        query = "SELECT * FROM rules.rulesets WHERE sid = "  
        self.display_details_in_modify_rule_box(query)

    def Modify_rule_box(self):
            complete_list = database().collect_all_sids()
            
            
            self.rule_modify_window = QWidget()
            self.rule_modify_window.setGeometry(450,250,1000,500)
            self.rule_modify_window.setWindowTitle("Modify Rule")
             
            self.retrievebutton  = QPushButton("Retrive Rule")

            self.find_signature = QLineEdit()
            self.complete_signatures = QCompleter(complete_list)
            self.find_signature.setCompleter(self.complete_signatures)

            self.find_signature.text()

            query = "SELECT * FROM rules.rulesets WHERE sid = " 
        
            self.retrievebutton.clicked.connect(lambda: self.display_details_in_modify_rule_box(query)) 
            
            self.Commit_rule_changes = QPushButton("OK")
            self.Commit_rule_changes.clicked.connect(self.Okay_Modify_rule_box_to_db)

            self.apply_rule_changes = QPushButton("Apply")
            self.apply_rule_changes.clicked.connect(self.Apply_Modify_rule_box_to_db)

            self.exit_modify_rules = QPushButton("Cancel")
            self.exit_modify_rules.clicked.connect(self.close_modify_rule_box)
        
            self.select_rule_status = QComboBox()
            self.select_rule_status.addItems(["Enabled","Disabled"])

            self.select_action = QComboBox()
            self.select_action.addItems(["","alert","log","pass","activate","dynamic"])

            self.select_protocol = QComboBox()
            self.select_protocol.addItems(["","tcp","udp","icmp"])

            self.edit_signature_number = QLineEdit()
            self.edit_rev_number = QLineEdit()

            self.edit_destination_network = QLineEdit()
            self.edit_destination_port = QLineEdit()
            self.edit_source_network = QLineEdit()
            self.edit_source_port = QLineEdit() 

            self.rule_edit = QTextEdit() 

            
            layout = QGridLayout()

            layout.addWidget(QLabel("Select rule"),1,0)
            layout.addWidget(self.find_signature,1,1)
            layout.addWidget(self.retrievebutton,1,2,1,2)

            layout.addWidget(QLabel("Signature number:"),2,0)
            layout.addWidget(self.edit_signature_number,2,1)

            layout.addWidget(QLabel("Rev:"),2,2)
            layout.addWidget(self.edit_rev_number,2,3)

            layout.addWidget(QLabel("Rule Status:"),2,6,)
            layout.addWidget(self.select_rule_status,2,7) 

            layout.addWidget(QLabel("Action:"),3,0) 
            layout.addWidget(self.select_action,3,1)
            layout.addWidget(QLabel("Protocol:"),3,2)
            layout.addWidget(self.select_protocol,3,3)

            layout.addWidget(QLabel("Source Network:"),4,0)
            layout.addWidget(self.edit_source_network,4,1) 

            layout.addWidget(QLabel("Source Port:"),4,2)
            layout.addWidget(self.edit_source_port,4,3)

            layout.addWidget(QLabel("Destination Network:"),4,4)
            layout.addWidget(self.edit_destination_network,4,5)

            layout.addWidget(QLabel("Destination Port:"),4,6)
            layout.addWidget(self.edit_destination_port,4,7)

            layout.addWidget(QLabel("Rule Body:"),5,0)
            layout.addWidget(self.rule_edit,6,0,1,8)
            
            layout.addWidget(self.Commit_rule_changes,7,7)
            layout.addWidget(self.apply_rule_changes,7,5)
            layout.addWidget(self.exit_modify_rules,7,3)


            self.rule_modify_window.setLayout(layout)
            self.rule_modify_window.show() 

    def close_modify_rule_box(self):
            self.rule_modify_window.close()
        
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

        rulemodifyaction = QAction("Modify Rule", self)
        rulemodifyaction.triggered.connect(self.Modify_rule_box)

        
        ruleMenu.addAction(importruleaction)
        ruleMenu.addAction(exportruleaction)
        ruleMenu.addAction(rulemodifyaction)
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
         
            query = "SELECT * FROM rules.rulesets"
            database().__class__.Last_Query = query

            result = database().get_data(query)
        
            for row_number, data_row in enumerate (result):
               
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item))) 

    
    def display_enabled_rules(self):
      
            self.table_widget.clearContents()

            query = "SELECT * FROM rules.rulesets WHERE rulestatus ='Enabled'"
            database().__class__.Last_Query = query

            result = database().get_data("SELECT * FROM rules.rulesets WHERE rulestatus ='Enabled'")

            for row_number, data_row in enumerate (result):
               
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item)))
                
   
    
    def display_disabled_rules(self):
      
            self.table_widget.clearContents()

            query = "SELECT * FROM rules.rulesets WHERE rulestatus ='Disabled'"
            database().__class__.Last_Query = query 
            

            result = database().get_data(query)

            for row_number, data_row in enumerate (result):
                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item)))

         

#This is for the filtered rules

    def display_filtered_rules(self):

           self.table_widget.clearContents()

           Queryheader_1 = str(self.first_title_combobox.currentText())
           Queryconditional_1 = str(self.first_conditional_combobox.currentText())
           Querysearchinput_1 = str(self.first_search_input.text())
           Queryoperational_1 = str(self.first_operator_combobox.currentText())
           
           Queryheader_2 = str(self.second_title_combobox.currentText())
           Queryconditional_2 = str(self.second_conditional_combobox.currentText())
           Querysearchinput_2 = str(self.second_search_input.text())
           Queryoperational_2 = str(self.second_operator_combobox.currentText())

           Queryheader_3 = str(self.third_title_combobox.currentText())
           Queryconditional_3 = str(self.third_conditional_combobox.currentText())
           Querysearchinput_3 = str(self.third_search_input.text())
           Queryoperational_3 = str(self.third_operator_combobox.currentText())

           Queryheader_4 = str(self.fouth_title_combobox.currentText())
           Queryconditional_4 = str(self.fourth_conditional_combobox.currentText())
           Querysearchinput_4 = str(self.fourth_search_input.text())
           Queryoperational_4 = str(self.fourth_operator_combobox.currentText())

           Queryheader_5 = str(self.fifth_title_combobox.currentText())
           Queryconditional_5 = str(self.fifth_conditional_combobox.currentText())
           Querysearchinput_5 = str(self.fifth_search_input.text())
           Queryoperational_5 = str(self.fifth_operator_combobox.currentText())

           search().__class__.Queryheader_1 = Queryheader_1
           search().__class__.Queryconditional_1 = Queryconditional_1
           search().__class__.Querysearchinput_1 = Querysearchinput_1
           search().__class__.Queryoperational_1 = Queryoperational_1

           search().__class__.Queryheader_2 = Queryheader_2
           search().__class__.Queryconditional_2 = Queryconditional_2
           search().__class__.Querysearchinput_2 = Querysearchinput_2
           search().__class__.Queryoperational_2 = Queryoperational_2

           search().__class__.Queryheader_3 = Queryheader_3
           search().__class__.Queryconditional_3 = Queryconditional_3
           search().__class__.Querysearchinput_3 = Querysearchinput_3
           search().__class__.Queryoperational_3 = Queryoperational_3

           search().__class__.Queryheader_4 = Queryheader_4
           search().__class__.Queryconditional_4 = Queryconditional_4
           search().__class__.Querysearchinput_4 = Querysearchinput_4
           search().__class__.Queryoperational_4 = Queryoperational_4

           search().__class__.Queryheader_5 = Queryheader_5
           search().__class__.Queryconditional_5 = Queryconditional_5
           search().__class__.Querysearchinput_5 = Querysearchinput_5
           search().__class__.Queryoperational_5 = Queryoperational_5
          
           query = search().create_query_line()
           database().__class__.Last_Query = query

           result = database().get_data(search().create_query_line())

           for row_number, data_row in enumerate (result):   

                for col_number, item in enumerate (data_row):
                        self.table_widget.setItem(row_number,col_number,QTableWidgetItem(str(item)))
           
           search().clear_query_input() 
#This function loads the intial data into the table from the database and displays it.  

app = QApplication(sys.argv)
mygui = MyGui()
 
sys.exit(app.exec_())
