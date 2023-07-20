###################################################################
#####################  DERIVATIVE ABP   ###########################
##### Shiva Kumar K, Payal Upadhyaya, Mahesh Ram Kuppuswamy #######

# importing the module
import json
import pexpect
import pprint
import time
import requests
import urllib3
import getpass
import collections
from collections import OrderedDict
from operator import getitem
import time
import os
import datetime
import json
import pdb
global command_dict
command_dict = {}

def connection_FO(ip_address):
    print("ssh to FO")
    time.sleep(1)
    child = pexpect.spawn('ssh -o StrictHostKeyChecking=accept-new admin@' + ip_address, timeout=45)
    time.sleep(3)
    child.sendline("\n")
    child.expect(".*: ")
    child.sendline("\n")
    child.expect(".*# ")
    child.sendline("conf t")
    child.expect(".*# ")
    print("######***Connected to switch***" + ip_address)
    return child
def send_command(child,ip_address,command):
    print("********** Event #######" + "******")
    now = datetime.datetime.now()
    time.sleep(1)
    for sub_command in command:
        child.sendline(sub_command)
        child.expect(".*# ")
        print(child.after)
        time.sleep(1)
    child.sendline('exit')
    child.expect(".*# ")
    #child.close()

# libs
def check_and_add(listoflist, element ,name_to_action_dict):

    if not element["name"] in listoflist:
        listoflist.append(element["name"])
    return listoflist


def create_command_from_dict(command_dict, access_list_ds, name_to_action_dict):
    if  not command_dict:
        # first time we are configuring, hence add all basic commands as well
        command_dict["port_access"] = []
        command_dict["port_access"].append("class abp-ip permit-any")
        command_dict["port_access"].append("10000 match any any any app-category any app any count")
        command_dict["port_access"].append("port-access abp derivative_abp")
        command_dict["port_access"].append("10000 class abp-ip permit-any")
    
    # command_dict already present, no need of basic config
    # we need to check access_list_ds and 
    #   add class if not present, 
    #   add match statement if not present 
    #   add class to abp policy if not present
    # start with permit
    if not len(access_list_ds["permit"]) == 0:
        # we need to add access list 
        if not "permit" in command_dict.keys():
            # cli's for permit is not there
            command_dict["permit"] = []
            command_dict["permit"].append("class abp-ip permit_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip permit_list" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["permit"]:
            # check if cli already there in previous iteration
            # need to optimise it for ignoring existing commands
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["permit"])):
                match_num = len(command_dict["permit"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["permit"].append(cmd)
    if not len(access_list_ds["deny"]) == 0:
        # we need to add access list 
        if not "deny" in command_dict.keys():
            # cli's for deny is not there
            command_dict["deny"] = []
            command_dict["deny"].append("class abp-ip deny_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip deny_list action drop" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["deny"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["deny"])):
                match_num = len(command_dict["deny"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["deny"].append(cmd)

    if not len(access_list_ds["dscpcs1"]) == 0:
        # we need to add access list 
        if not "dscpcs1" in command_dict.keys():
            # cli's for dscpcs1 is not there
            command_dict["dscpcs1"] = []
            command_dict["dscpcs1"].append("class abp-ip dscpcs1_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip dscpcs1_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["dscpcs1"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["dscpcs1"])):
                match_num = len(command_dict["dscpcs1"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["dscpcs1"].append(cmd)

    if not len(access_list_ds["dscpcs2"]) == 0:
        # we need to add access list 
        if not "dscpcs2" in command_dict.keys():
            # cli's for dscpcs2 is not there
            command_dict["dscpcs2"] = []
            command_dict["dscpcs2"].append("class abp-ip dscpcs2_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip dscpcs2_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["dscpcs2"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["dscpcs2"])):
                match_num = len(command_dict["dscpcs2"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["dscpcs2"].append(cmd)

    if not len(access_list_ds["dscpcs3"]) == 0:
        # we need to add access list 
        if not "dscpcs3" in command_dict.keys():
            # cli's for dscpcs3 is not there
            command_dict["dscpcs3"] = []
            command_dict["dscpcs3"].append("class abp-ip dscpcs3_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip dscpcs3_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["dscpcs3"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["dscpcs3"])):
                match_num = len(command_dict["dscpcs3"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["dscpcs3"].append(cmd)
    
    if not len(access_list_ds["dscpcs4"]) == 0:
        # we need to add access list 
        if not "dscpcs4" in command_dict.keys():
            # cli's for dscpcs4 is not there
            command_dict["dscpcs4"] = []
            command_dict["dscpcs4"].append("class abp-ip dscpcs4_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip dscpcs4_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["dscpcs4"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["dscpcs4"])):
                match_num = len(command_dict["dscpcs4"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["dscpcs4"].append(cmd)

    if not len(access_list_ds["dscpcs5"]) == 0:
        # we need to add access list 
        if not "dscpcs5" in command_dict.keys():
            # cli's for dscpcs5 is not there
            command_dict["dscpcs5"] = []
            command_dict["dscpcs5"].append("class abp-ip dscpcs5_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip dscpcs5_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["dscpcs5"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["dscpcs5"])):
                match_num = len(command_dict["dscpcs5"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["dscpcs5"].append(cmd)
    
    if not len(access_list_ds["lp1"]) == 0:
        # we need to add access list 
        if not "lp1" in command_dict.keys():
            # cli's for lp1 is not there
            command_dict["lp1"] = []
            command_dict["lp1"].append("class abp-ip lp1_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip lp1_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["lp1"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["lp1"])):        
                match_num = len(command_dict["lp1"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["lp1"].append(cmd)

    if not len(access_list_ds["lp4"]) == 0:
        # we need to add access list 
        if not "lp4" in command_dict.keys():
            # cli's for lp4 is not there
            command_dict["lp4"] = []
            command_dict["lp4"].append("class abp-ip lp4_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip lp4_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["lp4"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["lp4"])):        
                match_num = len(command_dict["lp4"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["lp4"].append(cmd)

    if not len(access_list_ds["lp7"]) == 0:
        # we need to add access list 
        if not "lp7" in command_dict.keys():
            # cli's for lp7 is not there
            command_dict["lp7"] = []
            command_dict["lp7"].append("class abp-ip lp7_list")
            index = len(command_dict["port_access"])
            index1 = index*10
            cmd = "%s class abp-ip lp7_list action dscp cs1" % index1
            command_dict["port_access"].append(cmd)
        for app in access_list_ds["lp7"]:
            app_cmd = "app %s count" % app
            if not list(filter(lambda x: app_cmd in x, command_dict["lp7"])):
                match_num = len(command_dict["lp7"])
                app_cat = name_to_action_dict[app]["category"]
                cmd = "%s match any any any app-category %s app %s count" % (match_num*10, app_cat, app)
                command_dict["lp7"].append(cmd)
    
    return command_dict  

def get_cpdi_table_top_application():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ip_add = "10.10.31.52"
    creds = {"username": "admin", "password": ""}

    session = requests.Session()
    try:
      login = session.post(f"https://{ip_add}/rest/v10.04/login", data=creds, verify=False)
      print(f"This is the login code: {login.status_code}")
      firmware = session.get(f"https://{ip_add}/rest/v10.13/firmware", verify=False)
      my_firmware = firmware.json()['current_version']
      print(f"My firmware is: {my_firmware}")
      file_input = session.get(f"https://{ip_add}/rest/v10.13/system/traffic_insight_application_flows?attributes=client_role,client_ip,application_id,traffic_insight_instance,flow_statistics,destination_ip,client_mac_addr,application_name,application_url&depth=2", verify=False)
      file_temp_input = file_input.json()
      count = 1
      cpdi_dict = collections.defaultdict(dict)
      app_flow_data_dict = collections.defaultdict(dict)

      for key,value in file_temp_input.items() :
          cpdi_dict[count]['app-id'] = value['application_id']
          cpdi_dict[count]['app-name'] = value['application_name']
          cpdi_dict[count]['app-url'] = value['application_url']
          cpdi_dict[count]['client-ip'] = value['client_ip']
          cpdi_dict[count]['client-role'] = value['client_role']
          cpdi_dict[count]['client-mac'] = value['client_mac_addr']
          cpdi_dict[count]['tx-statistics'] = value['flow_statistics']['packets_tx']
          count += 1
      index =1
      temp_data = dict(sorted(cpdi_dict.items(), reverse = True , key=lambda x: x[1]["tx-statistics"]))
      for key,value in temp_data.items() :
          app_flow_data_dict[index] = value
          index += 1
      print("Get the top applications consuming AOS-CX resources by browsing internet on two VM's")
      with open("cpdi_topN.json", "w") as fp:
           json.dump(app_flow_data_dict , fp)
      print("##############################\n")
      print(app_flow_data_dict)
    finally:
      logout = session.post(f"https://{ip_add}/rest/v10.04/logout")
      print(f"This is the logout code: {logout.status_code}")
# Main

n = 1
while n <= 1 :
    
    # For each 12 minutes interval
    # Open application_priority.json & latest queried cpdi table json file.

    with open('application_priority.json') as json_file:
        data_app_prio = json.load(json_file)
        
    # Opening JSON file

    get_cpdi_table_top_application()
    with open('cpdi_topN.json') as json_file:
        data_cpdi = json.load(json_file)

    # Now we have the top apps and their equivalent priority to be configured by abp or allow/deny them
    # stitch them together

    # have one array for eeach of allow,deny,dscp and local prio
    # for POC, we are having only below dscp and local-prio values, anything other than it is optimised and rounded off to nearest of below value
    # dscp cs1,cs2cs3,cs4,cs5, local-piority - 0,3,7

    dscp_cs1_list = []
    dscp_cs2_list = []
    dscp_cs3_list = []
    dscp_cs4_list = []
    dscp_cs5_list = []
    local_prio_1_list = []
    local_prio_4_list = []
    local_prio_7_list = []
    permit_list = []
    deny_list = []

    access_list_ds = {}
    access_list_ds["dscpcs1"] = dscp_cs1_list
    access_list_ds["dscpcs2"] = dscp_cs2_list
    access_list_ds["dscpcs3"] = dscp_cs3_list
    access_list_ds["dscpcs4"] = dscp_cs4_list
    access_list_ds["dscpcs5"] = dscp_cs5_list
    access_list_ds["lp1"] = local_prio_1_list
    access_list_ds["lp4"] = local_prio_4_list
    access_list_ds["lp7"] = local_prio_7_list
    access_list_ds["permit"] = permit_list
    access_list_ds["deny"] = deny_list

    config_abp_array = []
    name_to_action_dict = {}

    for cpdi_app in data_cpdi:
        # check if entry there in data_apps_prio
        # if there set appropriate prio, else, ignore it, without any config, default allowed without any abp policy on it
        appid = str(data_cpdi[cpdi_app]["app-id"])

        if appid in data_app_prio["app-id"]:
            # check whats the action and action parameter
            entry = {}
            entry["name"] = data_app_prio["app-id"][appid]["name"]
            entry["action"] = data_app_prio["app-id"][appid]["action"]
            entry["action_value"] = data_app_prio["app-id"][appid]["action_value"]
            entry["counter"] = 3
            # have a app-name to action dict for command formation reference
            app_name = data_app_prio["app-id"][appid]["name"]
            if not app_name in name_to_action_dict.keys():
                name_to_action_dict[app_name] = {}
                name_to_action_dict[app_name]["category"] = data_app_prio["app-id"][appid]["category"]
                name_to_action_dict[app_name]["action"] = data_app_prio["app-id"][appid]["action"]
                name_to_action_dict[app_name]["action_value"] = data_app_prio["app-id"][appid]["action_value"]
                name_to_action_dict[app_name]["counter"] = 3
            else:
                name_to_action_dict[app_name]["counter"] += 1

            # create and append all these data to config_abp_array so that we can configure command out of it later
            if entry["action"] == "permit":
                permit_list = check_and_add(permit_list, entry, name_to_action_dict)
            elif entry["action"] == "deny":
                deny_list = check_and_add(deny_list, entry, name_to_action_dict)
            elif entry["action"] == "dscp":
                if entry["action_value"] == "CS5" or entry["action_value"] == "cs5":
                    dscp_cs5_list = check_and_add(dscp_cs5_list, entry, name_to_action_dict)
                elif entry["action_value"] == "CS2" or entry["action_value"] == "cs2":
                    dscp_cs2_list = check_and_add(dscp_cs2_list, entry, name_to_action_dict)
                elif entry["action_value"] == "CS3" or entry["action_value"] == "cs3":
                    dscp_cs3_list = check_and_add(dscp_cs3_list, entry, name_to_action_dict)
                elif entry["action_value"] == "CS4" or entry["action_value"] == "cs4":
                    dscp_cs4_list = check_and_add(dscp_cs4_list, entry, name_to_action_dict)
                else:
                    # for now any other values other than [cs1,cs2,cs3,cs4,cs5] are defaulted to cs1
                    # need to improve logic to include all dscp values or to match nearest value to the cs1-5 value.
                    dscp_cs1_list = check_and_add(dscp_cs1_list, entry, name_to_action_dict)
            elif entry["action"] == "local-priority":
                if entry["action_value"] == "1":
                    local_prio_1_list = check_and_add(local_prio_1_list, entry, name_to_action_dict)
                elif entry["action_value"] == "7":
                    local_prio_7_list = check_and_add(local_prio_7_list, entry, name_to_action_dict)
                else:
                    #for now any other values other than [cs1,cs2,cs3,cs4,cs5] are defaulted to cs1
                    # need to improve logic to include all dscp values or to match nearest value to the cs1-5 value.
                    local_prio_4_list = check_and_add(local_prio_4_list, entry, name_to_action_dict)
            else:
                print("did not match any predefined values, hence skipping abp config")

    # class abp-ip permit_class_list
        # 10 match any any any app-category social-networking app twitter count
        # 20 match any any any app-category social-networking app facebook count
        # 30 match any any any app-category social-networking app any count
    # class abp-ip deny_class_list
        # 10 match any any any app-category streaming app youtube count
        # 20 match any any any app-category streaming app youtube-tv count
    # class abp-ip dscp_cs1_class_list
        # 10 match any any any app-category streaming app youtube count
    # class abp-ip dscp_cs5_class_list
        # 10 match any any any app-category streaming app youtube count
    # class abp-ip lp_1_class_list
        # 10 match any any any app-category streaming app youtube count
    # class abp-ip lp_7_class_list
        # 10 match any any any app-category streaming app youtube count

    # port-access abp youtube_block
        # 10 class abp-ip youtube action drop
        # 20 class abp-ipv6 youtube6 action drop
        # 40 class abp-ip permit-any
        # 50 class abp-ipv6 permitv6-any

    # initialise the Cmd variable which shall be used to send commands to switch
    # if it is not existent
    ip_address = "10.10.31.52"
    FO_con = connection_FO(ip_address)
    command_dict = create_command_from_dict(command_dict, access_list_ds, name_to_action_dict)
    for key in command_dict.keys():
        if key not in 'port_access':
           send_command(FO_con,ip_address,command_dict.get(key))
    for key in command_dict.keys():
        if key in 'port_access':
           send_command(FO_con,ip_address,command_dict.get(key))
    pprint.pprint(command_dict)
    n += 1
    time.sleep(7)
