#!/usr/bin/env python

import re
import os
import sys
import json
import time
import string
import boto3
import pexpect
import botocore
import subprocess
from random import *
from datetime import datetime
from optparse import OptionParser

'''
This script will:
    Check if CVE migration, set appropriate filenames
    Check if script was executed previously via existence of cached files in local directory, load into memory if exist
    Create boto3 ec2 client to interact with AWS, exit if error with access key or secret key
    Check if destination image name contains "Hourly", set hourly flag to true
    Check user-provide Instance ID in AWS(Exist?)
    Check if management IP accessible and has same user-provided instance id to prevent user error and conflict
    Gather hostname and store in cached file if does not exist
    For BYOL only, gather new regkey(s) from user input or from Source AMI Instance after Allow-Move on existing RegKey
    Check UCS file, log on to BIG-IP via ssh to create with md5 checksum and download to local directory if needed
        tmsh save /sys config ucs
    Gather AWS Info from Source BIG-IP
        describe-instance
    Gather Tags for instance in AWS, allow user to force migration with -f flag if instance was previously created with CloudFormation
    Gather source AMI's network interfaces from AWS
    Sets ENIs DeleteOnTermination to False so can simply re-use
        modify_network_interface_attribute
    Terminates source AMI Instance (so can detach ENIs)
        terminate_instances
    Launch New AMI Instance with ENI Ids from Source AMI Instance above
        create_instances
    Log on to BIG-IP via ssh to set hostname
        modify sys global-settings hostname
    For BYOL only, install license(from new Regkey or from Source AMI Instance after Allow-Move on existing RegKey )
        install sys license registration-key
    Install UCS (with no-license flag to not overwrite new license )
        tmsh load sys ucs filename no-license
'''

def generate_masterkey():
    characters = string.ascii_letters + string.punctuation  + string.digits
    password =  "".join(choice(characters) for x in range(randint(8, 16)))
    #print password
    return password

def debug_conn ( conn ):
   print "Before Match:"
   print conn.before
   print "After Match:"
   print conn.after
   print ""

def pexpect_save_clean_ucs ( user, ssh_key, password, host, print_debug ):
  MY_TIMEOUT = 120
  SSH_NEWKEY = 'Are you sure you want to continue connecting'
  masterkey = generate_masterkey()

  print "SSH'ing to : " + user + "@" + host
  #conn = pexpect.spawn("ssh -i " + ssh_key " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  user + "@" + host)
  conn = pexpect.spawn("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  user + "@" + host)

  # start of can remove after use ssh key to login?
  match_value = conn.expect([SSH_NEWKEY, '[Pp]assword:', pexpect.EOF, pexpect.TIMEOUT], timeout=MY_TIMEOUT);

  if print_debug == 2: debug_conn(conn)

  time.sleep(1)
  if match_value == 0:
      print "Matched new key warning"
      conn.sendline ( "yes" )
  elif match_value == 1:
      print "Matched Password prompt. Sending Password"
      conn.sendline ( password )
  time.sleep(1)
  # end of can remove after use ssh key to login?

  #Hopefully eventually get here
  match_value = conn.expect('\(tmos\)#', timeout=MY_TIMEOUT)

  if print_debug == 2: debug_conn(conn)

  if match_value == 0:
      # tmsh prompt
      print "Matched tmsh prompt! Running save-clean-ucs ...";
      conn.sendline("run util bash -c 'bash /tmp/save-clean-ucs'")

  match_value = conn.expect('enter password:', timeout=MY_TIMEOUT)

  if print_debug == 2: debug_conn(conn)

  if match_value == 0:
      print "Matched enter password prompt. Sending master key"
      conn.sendline ( masterkey )

  match_value = conn.expect('password again:', timeout=MY_TIMEOUT)

  if print_debug == 2: debug_conn(conn)

  if match_value == 0:
      print "Matched password again prompt. Sending master key"
      conn.sendline ( masterkey )

  match_value = conn.expect(['Done. Restore from', 'Unable to save configs'], timeout=MY_TIMEOUT)

  if match_value == 0:
      print "Matched Done saving clean config.  Need to download /var/local/ucs/cve-2016-2084-remediation/* to local dir..."

  if match_value == 1:
      sys.exit("Unable to save configs to /var/local/ucs/cve-2016-2084-remediation; move/remove /var/local/ucs/cve-2016-2084-remediation. Exiting...")

  return masterkey

def pexpect_restore_clean_ucs ( user, ssh_key, password, host, masterkey, print_debug ):
  MY_TIMEOUT = 60
  SSH_NEWKEY = 'Are you sure you want to continue connecting'

  print "SSH'ing to : " + user + "@" + host
  conn = pexpect.spawn("ssh -i " + ssh_key + " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  user + "@" + host)

  # Hopefully eventually get here
  match_value = conn.expect('\(tmos\)#', timeout=MY_TIMEOUT)
  if print_debug == 2: debug_conn(conn)
  
  if match_value == 0:
      # print "Matched tmsh prompt! Now run the restore-clean-ucs that was uploaded to BIG-IP
      print "Matched tmsh prompt! Running restore-clean-ucs ...";
      conn.sendline("run util bash -c 'bash /tmp/restore-clean-ucs'")
  

  # An array of 2 to hold masterkey1 and masterkey2
  masterkeys = []
  # get masterkey1 passed in as parameter
  masterkeys.append(masterkey)
  masterkeys.append(generate_masterkey())
  print "Master Key 1 = " + masterkeys[0]
  print "Master Key 2 = " + masterkeys[1]
  for masterkey in masterkeys: # iterate 2 times with different masterkey1 to restore UCS and masterkey2 to set on BIG-IP
    # Two similar prompts for master key(password) used when saving ucs and final master key

    match_value = conn.expect('enter password:', timeout=MY_TIMEOUT)
    if print_debug == 2: debug_conn(conn)

    if match_value == 0:
        print "Matched enter password prompt. Sending master key"
        conn.sendline ( masterkey )

    match_value = conn.expect('password again:', timeout=MY_TIMEOUT)
    if print_debug == 2: debug_conn(conn)

    if match_value == 0:
        print "Matched password again prompt. Sending master key"
        conn.sendline ( masterkey )

  match_value = conn.expect(['Saving Ethernet mapping...done', 'Saving Ethernet mapping...failed'], timeout=MY_TIMEOUT)
  if print_debug == 1: debug_conn(conn)

  if match_value == 0:
      print "Matched Saving Ethernet mapping...done.  Restore completed"

  if match_value == 1:
      print "Matched Saving Ethernet mapping...failed. The message is cosmetic and is not a cause for concern.  SOL11772107. Restore completed"

class DateTimeEncoder(json.JSONEncoder):
    # http://stackoverflow.com/questions/11875770/how-to-overcome-datetime-datetime-not-json-serializable-in-python
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()

        return json.JSONEncoder.default(self, o)


def ssh_cmd ( user, ssh_key, host, cmd_str, debug, timeout=30, host_key_check=False, bg_run=False):                                                                                                 
    """SSH'es to a host using the supplied credentials and executes a command.                                                                                                 
    Throws an exception if the command doesn't return 0.                                                                                                                       
    bgrun: run command in the background"""

    p = subprocess.Popen(["ssh", 
                          "-i", 
                          ssh_key, 
                          "-q", 
                          "-oStrictHostKeyChecking=no", 
                          "-oUserKnownHostsFile=/dev/null", 
                          user + "@" + host,  
                          cmd_str
                          ], stdout=subprocess.PIPE)
    
    # print  "PID = " + str(p.pid) + \
    #        " :running ssh cmd: \n" + \
    #        "ssh -i " + \
    #        ssh_key + \
    #        " -q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null " + \
    #        user + "@" + host + " \'" + \
    #        cmd_str + \
    #        "\'" 
    #print  "running cmd: \n" + cmd_str
    if debug > 0:
        print  "RUNNING cmd: " + cmd_str 

    #And wait for process to finish before moving on to the next
    while p.poll() == None:
        time.sleep(1)
        p.poll()
    (results, errors) = p.communicate()
    if errors == "" or errors == None:
        return results
    else:    
        return errors                                                                                                                                    

def scp_download_cmd ( user, ssh_key, host, remote_file, local_file, timeout=30, host_key_check=False, bg_run=False ):
    """
    Downloads a file via SCP
    """

    if local_file == "" or local_file == None:
        local_file = "."

    # Download/ Save to local disk
    p = subprocess.Popen([
                          "scp", 
                          "-i", 
                          ssh_key, 
                          "-q", 
                          "-oStrictHostKeyChecking=no", 
                          "-oUserKnownHostsFile=/dev/null", 
                          user + "@" + host + ":" + remote_file, 
                          local_file 
                          ])

    # print "PID = " + str(p.pid) + \
    #       " :running scp command: \n" + \
    #       "scp -i " + \
    #       ssh_key + " " + \
    #       user + "@" + host + ":" + remote_file + " " + \
    #       local_file

    print "Downloading file: " + remote_file + " from host: " + host
    #And wait for each process to finish before moving on to the next
    while p.poll() == None:
        time.sleep(1)
        p.poll()
    (results, errors) = p.communicate()
    if errors == "" or errors == None:
        return results
    else:
        #print "errors are:"
        return errors


def scp_upload_cmd ( user, ssh_key, host, local_file, remote_file, timeout=30, host_key_check=False, bg_run=False ):
    """
    Uploads a file via SCP
    """

    # Download/ Save to local disk
    p = subprocess.Popen([
                          "scp", 
                          "-i", 
                          ssh_key, 
                          "-q", 
                          "-oStrictHostKeyChecking=no", 
                          "-oUserKnownHostsFile=/dev/null", 
                          local_file, 
                          user + "@" + host + ":" + remote_file,                           
                          ])
    # print "PID = " + str(p.pid) + \
    #       " :running scp command: \n" + \
    #       "scp -i " + \
    #       ssh_key + " " + \
    #       local_file + \
    #       user + "@" + host + ":" + remote_file

    print "Uploading file: " + local_file + " to host: " + host

    #And wait for each process to finish before moving on to the next
    while p.poll() == None:
        time.sleep(1)
        p.poll()
    (results, errors) = p.communicate()
    if errors == "" or errors == None:
        return results
    else:
        #print "errors are:"
        return errors

def is_non_zero_file(fpath):
    return True if os.path.isfile(fpath) and os.path.getsize(fpath) > 0 else False

def upload_check_md5sum_file(username, ssh_key, management_ip, local_file_md5, remote_file_md5, debug_level):

    # scp f5-<instanceid>.ucs.md5 from local to /var/local/ucs on BIG-IP
    scp_output = scp_upload_cmd (
                                    user=username, 
                                    ssh_key=ssh_key, 
                                    host=management_ip, 
                                    remote_file=remote_file_md5,
                                    local_file=local_file_md5,  
                                    timeout=30, 
                                    host_key_check=False, 
                                    bg_run=False
                                  ) 
    if debug_level > 0:
        print "scp_output: "
        print scp_output

    # Check if md5sum is valid else sys.exit
    cmd_str = "run util bash -c 'md5sum -c " + remote_file_md5 + "'"
    ssh_output = ssh_cmd(
                            user=username, 
                            ssh_key=ssh_key, 
                            host=management_ip, 
                            cmd_str=cmd_str,
                            debug=debug_level,
                            timeout=30, 
                            host_key_check=False, 
                            bg_run=False
                        ) 
    if debug_level > 0:
        print "cmd_output: "
        print ssh_output

    match = re.search('(: OK)', ssh_output)
    if not match:
        sys.exit("md5sum file does not match.  Exiting...")

def main():
    parser = OptionParser()
    parser.add_option("-f", "--force", action="store_true", dest="force", default=False, help="Force Migration")
    parser.add_option("-C", "--CVE", action="store_true", dest="cve", default=False, help="cve-2016-2084-remediation")
    parser.add_option("-k", "--ssh-key", action="store", type="string", dest="ssh_key", help="SSH Key File - full path" )
    parser.add_option("-i", "--src-instance-id", action="store", type="string", dest="src_instance_id", help="Source Big-IP instance-id")
    parser.add_option("-m", "--management-ip", action="store", type="string", dest="management_ip", help="Management Ip" )
    parser.add_option("-u", "--username", action="store", type="string", dest="username", help="Big-IP admin username" )
    parser.add_option("-p", "--password", action="store", type="string", dest="password", help="Big-IP admin password" )
    parser.add_option("-d", "--dest-ami", action="store", type="string", dest="dest_ami", help="Destination Big-IP AMI" )
    parser.add_option("-t", "--dest-instance-type", action="store", type="string", dest="dest_instance_type", help="Destination Instance Type" )
    parser.add_option("--debug-level", action="store", type="int", dest="debug_level", help="debug level print debug (0-9)", default=0 )
    # Allow for user to provide new regkey when migrate from Util to BYOL
    parser.add_option("-r", "--regkeys", action="store", type="string", dest="regkeys", help="Comma seperated list of regkeys" )
  # These may be picked up in ~/.aws/credentials instead if exist in user environment via AWS CLI install
    parser.add_option("-R", "--aws-region", action="store", type="string", dest="aws_region", help="AWS Region", default=None )
    parser.add_option("-A", "--aws-access-key", action="store", type="string", dest="aws_access_key", help="AWS Access Key", default=None )
    parser.add_option("-S", "--aws-secret-key", action="store", type="string", dest="aws_secret_key", help="AWS Secret Key", default=None )
    (options, args) = parser.parse_args()

    # Gather variables from options
    force = options.force
    cve = options.cve
    ssh_key = options.ssh_key
    ssh_key_name = os.path.splitext(os.path.basename(ssh_key))[0]
    src_instance_id = options.src_instance_id
    username = options.username
    password = options.password 
    management_ip = options.management_ip
    dest_ami = options.dest_ami
    dest_instance_type = options.dest_instance_type
    debug_level = options.debug_level
    regkeys = options.regkeys
    aws_region = options.aws_region
    aws_access_key = options.aws_access_key
    aws_secret_key = options.aws_secret_key

    # Declare/set global variables/arrays/dicts
    image_hourly = False
    dest_image_hourly = False
    instance_in_aws = False
    new_instance_in_aws = False
    instance_accessible = False
    new_instance_accessible = False
    cached_license_filename_exist = False
    cached_hostname_filename_exist = False
    cached_instance_filename_exist = False
    cached_new_instance_filename_exist = False
    cached_hostname_filename = 'f5-' + src_instance_id + '.hostname'
    cached_license_filename = 'f5-' + src_instance_id + '-cached-bigip-license'
    cached_instance_filename = 'f5-' + src_instance_id + '-cached-instance.json'
    cached_new_instance_filename = 'f5-' + src_instance_id + '-cached-new-instance.json'
    cached_masterkey1_filename = 'f5-' + src_instance_id + '.masterkey1'
    user_instance_output = ""
    instance_output = ""
    new_instance_output = ""
    new_instance_id = ""
    license_file_content = ""
    remote_file = "/var/tmp/f5-" + src_instance_id + ".ucs"
    regkey_list = []
    dst_tags = []
    dest_enis = []
    
    # Check if CVE migration, set appropriate filenames
    if cve:
        local_file = 'f5-' + src_instance_id + "-clean.ucs"
        local_file_md5 = 'f5-' + src_instance_id + "-clean.ucs.md5"
        masterkey_filename = 'f5-' + src_instance_id + ".masterkey1"
    else:
        local_file = 'f5-' + src_instance_id + ".ucs"
        local_file_md5 = 'f5-' + src_instance_id + ".ucs.md5"

    # Check if script was executed previously via existence of cached files in local directory, load into memory if exist
    print "\n_____ANALYZING..."
    if is_non_zero_file(cached_instance_filename):  # Instance file
        with open(cached_instance_filename) as json_file:
            instance_output = json.load(json_file)
            cached_instance_filename_exist = True
            print "File " + cached_instance_filename + " exists in local directory from previous run."

    if is_non_zero_file(cached_hostname_filename):  # Hostname file
        with open(cached_hostname_filename) as hostname_file:
            hostname = hostname_file.read()
            cached_hostname_filename_exist = True
            print "File " + cached_hostname_filename + " exists in local directory from previous run."

    if is_non_zero_file(cached_license_filename):   # License file
        with open(cached_license_filename) as license_file:
            license_file_content = license_file.read()
            cached_license_filename_exist = True
            print "File " + cached_license_filename + " exists in local directory from previous run."

    if is_non_zero_file(local_file):    # UCS file
        cached_ucs_local_file_exist = True
        print "UCS file " + local_file + " exists in local directory from previous run."
        if is_non_zero_file(local_file_md5):    # UCS md5 checksum file
            print "md5sum file " + local_file_md5 + " for saved UCS exists in local directory from previous run."
            if cve:
                if is_non_zero_file(masterkey_filename):    # CVE masterkey1 file
                    print "masterkey file " + masterkey_filename + " for saved UCS exists in local directory from previous run."
                else:
                    sys.exit("Missing or empty masterkey file " + masterkey_filename + " for saved UCS.  Exiting...")
        else:
            sys.exit("Missing or empty md5 checksum file " + local_file_md5 + " for saved UCS.  Exiting...")

    if is_non_zero_file(cached_new_instance_filename):  # New instance file
        with open(cached_new_instance_filename) as json_file:
            new_instance_output = json.load(json_file)
            cached_new_instance_filename_exist = True
            print "File " + cached_new_instance_filename + " exists in local directory from previous run."
            new_instance_id = new_instance_output['Reservations'][0]['Instances'][0]['InstanceId']
            print "New Instance ID is " + new_instance_id

    # Create boto3 ec2 client to interact with AWS, exit if error with access key or secret key
    try: 
        client = boto3.client('ec2', region_name=aws_region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key )
    except botocore.exceptions.ClientError as e:
        print e
        sys.exit("Exiting...")

    # Check if destination image name contains "Hourly", set hourly flag to true
    dest_image = client.describe_images( ImageIds=[dest_ami] )
    dest_image_name = dest_image['Images'][0]['Name']
    print "Destination Image is " + dest_image_name

    match = re.search('(F5 Networks Hourly)', dest_image_name)
    if match: # Hourly else BYOL
        dest_image_hourly = True

    # Check user-provide Instance ID in AWS
    print "\n_____CHECKING user-provided Instance ID " + src_instance_id + " in AWS...Please wait..."
    try:        # Does Instance ID exist in AWS?
        user_instance_output = client.describe_instances( InstanceIds=[ src_instance_id ] )
        if debug_level > 0:
            print user_instance_output

        if user_instance_output['Reservations']:
            instance_status = user_instance_output['Reservations'][0]['Instances'][0]['State']['Name']
            print "Instance status is " + instance_status

            if not (instance_status == "terminated"):
                print "User-provided Instance ID exist in AWS...Need to terminate." # AWS instance exist and we need to terminate
                instance_in_aws = True
            else:
                print "User-provided Instance ID was terminated in AWS...No need to terminate." # AWS instance was terminated and we do not need to terminate
                instance_in_aws = False
                instance_status  = "terminated"
        else:   # AWS instance does not exist
            print "User-provided Instance ID does not exist in AWS...No need to terminate." # AWS instance does not exist and we do not need to terminate
            instance_in_aws = False
            instance_status  = "terminated"
    except botocore.exceptions.ClientError as e:            # AWS instance does not exist
        instance_in_aws = False
        print e
        print "Client-provided Instance ID does not exist in AWS...No need to terminate." # AWS instance does not exist and we do not need to terminate
        instance_status  = "terminated"

    # Check if management IP accessible and has same user-provided instance id to prevent user error and conflict
    print "\n_____ACCESSING BIG-IP at " + management_ip + " to check Instance ID...Please wait..."
    cmd_str = "run util bash -c 'curl http://169.254.169.254/latest/meta-data/instance-id'"
    ssh_output = ssh_cmd(  
                            user=username, 
                            ssh_key=ssh_key, 
                            host=management_ip, 
                            cmd_str=cmd_str, 
                            debug=debug_level, 
                            timeout=30, 
                            host_key_check=False, 
                            bg_run=False
                        ) 

    if debug_level > 0:
        print "cmd_output: "
        print ssh_output

    if ssh_output == "":
        print "Unable to access management IP " + management_ip + " to gather its Instance ID."
    elif ssh_output == src_instance_id: 
        # AWS instance is accessible "instance_accessible is TRUE"
        instance_accessible = True
        print "User provided Instance ID " + src_instance_id + " matches Instance ID at management IP " + management_ip
    elif (cached_new_instance_filename_exist and ssh_output == new_instance_id):    # AWS new instance was previously created 
            new_instance_in_aws = True
            new_instance_accessible = True
            print "New Instance ID " + new_instance_id + " matches Instance ID at management IP " + management_ip
    else: # wrong instance, exit
            print "Instance ID provided (" +  src_instance_id + ") is different from Instance ID (" + ssh_output + ") at management IP " + management_ip
            sys.exit("Please provide corresponding management IP for user-provided Instance ID.\nExiting...")
        
    # Gather hostname and store in cached file if does not exist
    if cached_hostname_filename_exist:
        pass
    elif instance_accessible:
        cmd_str = "list sys global-settings hostname"
        ssh_output = ssh_cmd(  
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

        match = re.search('hostname (.+)', ssh_output)
        hostname = match.group(1)

        with open(cached_hostname_filename, 'w') as outfile:
                        outfile.write(hostname)

        if debug_level > 0:
            print "Hostname is " + hostname
    else:
        sys.exit("File cached_hostname_filename does not exist in local directory. Instance inaccessible to create cached_hostname_filename. Exiting...")


    # For BYOL only, gather new regkey(s) from user input or from Source AMI Instance after Allow-Move on existing RegKey 
    print "\n_____CHECKING for license..."
    if not dest_image_hourly:
        if regkeys:
            regkey_list = regkeys.split(",")
        else:
            if cached_license_filename_exist:
                pass # Don't overwrite aws info cache if already exists ( allow for successive runs)
            elif instance_accessible:
                cmd_str = "show sys license"
                license_file_content = ssh_cmd(  
                                                user=username, 
                                                ssh_key=ssh_key, 
                                                host=management_ip, 
                                                cmd_str=cmd_str,
                                                debug=debug_level,
                                                timeout=30, 
                                                host_key_check=False, 
                                                bg_run=False
                                            )
                                 
                if debug_level > 3:
                    print "license cmd_output: "
                    print license_file_content   

                with open(cached_license_filename, 'w') as outfile:
                        outfile.write(license_file_content)
            else:
                sys.exit("No Reg Key provided by user. File cached_license_filename does not exist in local directory. Instance inaccessible to copy Allow-Move Reg Keys. Exiting...")

            # (tmos)# show sys license | grep -o '\([A-Z]\{5,7\}*\-[A-Z]\{5,7\}\)*'
            # ALDBE-TOBUQ-ETBLG-SGICR-EDQIUGF
            # ASGUMPP-DBUNBJF
            # BCJRKJE-OWXJDSV
            # BMBFNPU-WXFJZNM
            # CLGEQSP-MNITSZD
            license_output = license_file_content.split('\n')

            for line in license_output:
                match = re.search('([A-Z-]*-[A-Z-]{4,7})', line, flags=re.MULTILINE)
                if match:
                    regkey = match.group(0)
                    regkey_list.append(regkey)  # Gather regkey(s)

    print "Reg Key List: "
    print regkey_list

    # Check UCS file, create if does not exist
    print "\n_____CHECKING for UCS..."
    # Check if file exists locally and is not empty
    if is_non_zero_file(local_file):
        password    # To allow for successive runs
        print "UCS was previously saved"
    elif instance_accessible:
        # Create UCS
        if cve: # CVE migration
            # scp and run save-clean-ucs in /tmp on BIG-IP then download clean.ucs with md5 checksum
            print "CVE"
            remote_save_clean_ucs_file = "/tmp/save-clean-ucs"
            local_save_clean_ucs_file = "save-clean-ucs"
            remote_file = "/var/local/ucs/cve-2016-2084-remediation/clean.ucs"
            local_file = "f5-" + src_instance_id + "-clean.ucs"
            remote_var_local_ucs_file = "/var/local/ucs/clean.ucs"

            scp_output = scp_upload_cmd (
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                remote_file=remote_save_clean_ucs_file,
                                local_file=local_save_clean_ucs_file,  
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                              )
            if debug_level > 0:
                print "scp_output: "
                print scp_output
            
            # call function pexpect_save_clean_ucs which will return the masterkey used for encrypting UCS
            masterkey1 = pexpect_save_clean_ucs( username, ssh_key, password, management_ip, debug_level )
            print "Master Key 1 = " + masterkey1
            # save masterkey 1 into cached file to allow reruns
            with open(cached_masterkey1_filename, 'w') as outfile:
                    outfile.write(masterkey1)

        else: # Classic migration
            print "No CVE"
            remote_file = "/var/tmp/f5-" + src_instance_id + ".ucs"
            local_file = 'f5-' + src_instance_id + ".ucs"
            remote_var_local_ucs_file = "/var/local/ucs/" + local_file

            cmd_str = "save /sys ucs /var/tmp/f5-" + src_instance_id + ".ucs"
            ssh_output = ssh_cmd(
                                    user=username, 
                                    ssh_key=ssh_key, 
                                    host=management_ip, 
                                    cmd_str=cmd_str,
                                    debug=debug_level,
                                    timeout=30, 
                                    host_key_check=False, 
                                    bg_run=False
                                ) 
            if debug_level > 0:
                print "cmd_output: "
                print ssh_output

        # Copy UCS to /var/local/ucs on BIG-IP as restore-clean-ucs expects that so we can md5sum
        cmd_str = "run util bash -c 'cp " + remote_file + " /var/local/ucs'"
        ssh_output = ssh_cmd(
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

        # md5sum the copied UCS file in /var/local/ucs on BIG-IP
        cmd_str = "run util bash -c 'md5sum " + remote_var_local_ucs_file + " > " + remote_var_local_ucs_file + ".md5'"
        ssh_output = ssh_cmd(
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

        # Download the created clean UCS file
        scp_output = scp_download_cmd (
                                        user=username, 
                                        ssh_key=ssh_key, 
                                        host=management_ip, 
                                        remote_file=remote_file,
                                        local_file=local_file,  
                                        timeout=30, 
                                        host_key_check=False, 
                                        bg_run=False
                                      ) 
        if debug_level > 0:
            print "scp_output: "
            print scp_output

        # Download the created UCS md5sum file
        remote_file_md5 = remote_var_local_ucs_file + ".md5"
        local_file_md5 = local_file + ".md5"
        scp_output = scp_download_cmd (
                                        user=username, 
                                        ssh_key=ssh_key, 
                                        host=management_ip, 
                                        remote_file=remote_file_md5,
                                        local_file=local_file_md5,  
                                        timeout=30, 
                                        host_key_check=False, 
                                        bg_run=False
                                      ) 
        if debug_level > 0:
            print "scp_output: "
            print scp_output
    else:
        sys.exit("UCS file does not exist in local directory. Instance inaccessible to create and download UCS. Exiting...")



    # Gather AWS Info from Source BIG-IP
    # http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_instances
    # https://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Instance
    print "\n_____CHECKING AWS details for source BIG-IP..."
    if cached_instance_filename_exist:
        pass # Don't overwrite aws info cache if already exists ( allow for successive runs)
    elif instance_in_aws:
        instance_output = client.describe_instances(
            InstanceIds=[ src_instance_id ]
        )
        with open(cached_instance_filename, 'w') as outfile:
            json.dump(instance_output, outfile, indent = 2, ensure_ascii=False, cls=DateTimeEncoder)
    else:
        sys.exit("File cached_instance_filename does not exist. Instance does not exist in AWS to create cached_instance_filename. Exiting...")

    # Should Check if Instance was created via CFT (Tags will have have "aws:" in Key ) and prompt/warn if you want to continue
    # ex.
            #   "Value": "arn:aws:cloudformation:us-east-1:452013943082:stack/existing-stack-bigiq-license-pool-bigip-1nic/df896620-f5ce-11e5-8e4e-50d5cad95262", 
            #   "Key": "aws:cloudformation:stack-id"
            # }, 

    # Can't just blindly copy tags from src instance output as Tags may be auto-generated from Cloudformation
    #  An error occurred (InvalidParameterValue) when calling the CreateTags operation: Tag keys starting with 'aws:' are reserved for internal use
    src_tags = instance_output['Reservations'][0]['Instances'][0]['Tags']
    for tag in src_tags:
        if not tag['Key'].startswith('aws:'):
            dst_tags.append(tag)
        else:
            if force:
                print "Skipping tag starting with 'aws:' " + tag['Key']
            else:
                sys.exit("Instance was previously created with CloudFormation. Use -f flag to force migration. Instance is not terminated yet. Exiting...")

    # Unforunately, we can't just detach ENIs (only secondary ENIs) 
    # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#detach_eni
    # We can try setting "Delete On Termination" and Terminate the Instance
    # https://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.modify_network_interface_attribute
    # OR..... can have to gather all the NIC information from instance first
    # ex. output of 2nic AMI
    # src_instance.network_interfaces
    # [ec2.NetworkInterface(id='eni-e379609a'), ec2.NetworkInterface(id='eni-924851eb')]
    # print src_instance.network_interfaces_attribute
    # [{u'Status': 'in-use', u'MacAddress': '02:40:bd:0e:3c:09', u'SourceDestCheck': True, u'VpcId': 'vpc-bc2223d9', u'Description': 'Primary network interface', u'Association': {u'PublicIp': '52.35.186.82', u'PublicDnsName': 'ec2-52-35-186-82.us-west-2.compute.amazonaws.com', u'IpOwnerId': '452013943082'}, u'NetworkInterfaceId': 'eni-e379609a', u'PrivateIpAddresses': [{u'PrivateDnsName': 'ip-10-0-10-11.us-west-2.compute.internal', u'Association': {u'PublicIp': '52.35.186.82', u'PublicDnsName': 'ec2-52-35-186-82.us-west-2.compute.amazonaws.com', u'IpOwnerId': '452013943082'}, u'Primary': True, u'PrivateIpAddress': '10.0.10.11'}], u'PrivateDnsName': 'ip-10-0-10-11.us-west-2.compute.internal', u'Attachment': {u'Status': 'attached', u'DeviceIndex': 0, u'DeleteOnTermination': True, u'AttachmentId': 'eni-attach-f037bafa', u'AttachTime': datetime.datetime(2016, 1, 6, 20, 1, 20, tzinfo=tzutc())}, u'Groups': [{u'GroupName': 'BIG-IP-Mgmt', u'GroupId': 'sg-61796505'}, {u'GroupName': 'BIG-IP-HA-Channel', u'GroupId': 'sg-cc7b67a8'}], u'SubnetId': 'subnet-32ceda57', u'OwnerId': '452013943082', u'PrivateIpAddress': '10.0.10.11'}, {u'Status': 'in-use', u'MacAddress': '02:10:5f:97:6c:51', u'SourceDestCheck': True, u'VpcId': 'vpc-bc2223d9', u'Description': 'BIGIP-02-AZ2-Public-Int', u'Association': {u'PublicIp': '52.33.102.108', u'PublicDnsName': 'ec2-52-33-102-108.us-west-2.compute.amazonaws.com', u'IpOwnerId': '452013943082'}, u'NetworkInterfaceId': 'eni-924851eb', u'PrivateIpAddresses': [{u'PrivateDnsName': 'ip-10-0-11-11.us-west-2.compute.internal', u'Association': {u'PublicIp': '52.33.102.108', u'PublicDnsName': 'ec2-52-33-102-108.us-west-2.compute.amazonaws.com', u'IpOwnerId': '452013943082'}, u'Primary': True, u'PrivateIpAddress': '10.0.11.11'}, {u'PrivateDnsName': 'ip-10-0-11-100.us-west-2.compute.internal', u'Primary': False, u'PrivateIpAddress': '10.0.11.100'}, {u'PrivateDnsName': 'ip-10-0-11-101.us-west-2.compute.internal', u'Primary': False, u'PrivateIpAddress': '10.0.11.101'}], u'PrivateDnsName': 'ip-10-0-11-11.us-west-2.compute.internal', u'Attachment': {u'Status': 'attached', u'DeviceIndex': 1, u'DeleteOnTermination': False, u'AttachmentId': 'eni-attach-5fc84455', u'AttachTime': datetime.datetime(2016, 1, 6, 20, 16, 18, tzinfo=tzutc())}, u'Groups': [{u'GroupName': 'BIG-IP Virtual Traffic', u'GroupId': 'sg-48c4dd2c'}, {u'GroupName': 'BIG-IP-HA-Channel', u'GroupId': 'sg-cc7b67a8'}], u'SubnetId': 'subnet-02ceda67', u'OwnerId': '452013943082', u'PrivateIpAddress': '10.0.11.11'}]
    # And try to recreate in destination

    # Determine how many interfaces to work with
    network_interfaces_attributes = instance_output['Reservations'][0]['Instances'][0]['NetworkInterfaces']
    if debug_level > 0:
        print "Number of ENIs detected = " + str(len(network_interfaces_attributes))
    
    for eni_index in range(0, len(network_interfaces_attributes)):
        device_index = network_interfaces_attributes[eni_index]['Attachment']['DeviceIndex']
        if debug_level > 0:
            print "Processing DeviceIndex " + str(device_index)

        try: # Store ENIs in format for create-instance
            eni_obj = {}
            NetworkInterfaceId = network_interfaces_attributes[eni_index]['NetworkInterfaceId']
            eni_obj['NetworkInterfaceId'] = NetworkInterfaceId
            eni_obj['DeviceIndex'] = device_index # change from eni_index to device_index on 20160407
            dest_enis.append(eni_obj)

            if instance_in_aws: # Sets ENIs DeleteOnTermination to False so can simply re-use 
                AttachmentId = network_interfaces_attributes[eni_index]['Attachment']['AttachmentId']
                response = client.modify_network_interface_attribute (
                    NetworkInterfaceId=NetworkInterfaceId,
                    Attachment={ 
                                 'AttachmentId': AttachmentId,
                                 'DeleteOnTermination': False
                               }
                )
        except botocore.exceptions.ClientError as e:
            # If can't, interfaces might have just been deleted from a previous run, print AWS error
            print e 

    try: # Check if instance still exist and not terminated yet then we terminate
        print "Instance status is " + instance_status
        while instance_status != "terminated": 
            try: # Terminate Instance
                print "Terminating Instance Id: " + src_instance_id + "..."
                response = client.terminate_instances( InstanceIds=[ src_instance_id ] )
                # ex. output
                # {u'TerminatingInstances': [{u'InstanceId': 'i-e0e8da63', u'CurrentState': {u'Code': 48, u'Name': 'terminated'}, u'PreviousState': {u'Code': 48, u'Name': 'terminated'}}], 'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId': '92bca19b-7158-42ee-8317-b945c83050b9'}}
                # An error occurred (InvalidInstanceID.NotFound) when calling the TerminateInstances operation: The instance ID 'i-1f1e239c' does not exist
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    print "Instance does not exist"
                    break

            instance_status = response['TerminatingInstances'][0]['CurrentState']['Name']

            if instance_status == "terminated":
                print "Instance status is " + instance_status
                break

            print "Waiting 30 seconds"
            time.sleep(30)
    except botocore.exceptions.ClientError as e:
        print e


    print "\n_____PREPARING new instance..."
    if debug_level > 0:
        print "dest_enis: "
        print dest_enis

    # Create boto3 ec2 resource
    ec2 = boto3.resource('ec2', region_name=aws_region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key )

    # Gather Security Groups if none are applied to Interfaces. Need to check above and set flag if interfaces have groups assigned
    dest_group_ids = []
    instance_groups = instance_output['Reservations'][0]['Instances'][0]['SecurityGroups']
    for group in instance_groups:
        dest_group_ids.append(group['GroupId'])

    if debug_level > 0:
        print "dest_group_ids : "
        print dest_group_ids

    if dest_instance_type == "" or dest_instance_type == None:
        dest_instance_type = instance_output['Reservations'][0]['Instances'][0]['InstanceType']

    if debug_level > 0:
        print "dest_instance_type: "
        print dest_instance_type

    # Save New instance output
    # Don't overwrite aws info cache if already exists ( allow for successive runs)
    if cached_new_instance_filename_exist:
        dst_instance = ec2.Instance(id=new_instance_id)
        print "New Instance previously created is " + dst_instance.instance_id
    else: 
        try:
            print "Creating new instance..."
            new_instances = ec2.create_instances(
                MinCount=1,
                MaxCount=1,
                ImageId=dest_ami,
                KeyName=ssh_key_name,
                #SecurityGroupIds=dest_group_ids,
                InstanceType=dest_instance_type,
                NetworkInterfaces=dest_enis,
                EbsOptimized=instance_output['Reservations'][0]['Instances'][0]['EbsOptimized']
            )

            new_instance = new_instances[0]
            new_instance_id = new_instance.instance_id
            dst_instance = ec2.Instance(id=new_instance_id)
            sys.stdout.write("New Instance ID is ")
            print new_instance_id

            # Need to add Tags and various other attributes to Instance that weren't allowed in create_instance
            # Set Tags
            # https://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Instance.create_tags
            tag = dst_instance.create_tags( Tags=dst_tags )  
            print tag

            new_instance_output = client.describe_instances(
                InstanceIds=[ new_instance.instance_id ]
            )
            with open(cached_new_instance_filename, 'w') as outfile:
                json.dump(new_instance_output, outfile, indent = 2, ensure_ascii=False, cls=DateTimeEncoder)

            print "Waiting until Instance in Running state..."
            dst_instance.wait_until_running()
            print "Instance now in Running state..."
            print "Sleeping 15 minutes(900 seconds) until BIG-IP is booted\nPlease wait..."
            time.sleep(900)
        except botocore.exceptions.ClientError as e:
            print e 


    # Check if new BIG-IP instance is active before start to configure
    bigip_active = None        
    cmd_str = "show sys failover"
    print "\n_____ACCESSING BIG-IP at " + management_ip + " to check if active. Max 5 tries. Please wait..."
    count = 0
    while (not bigip_active and count < 5 ):    # Check 5 times
        ssh_output = ssh_cmd(  
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False,
                            )
        bigip_active = re.search('Failover active', ssh_output)

        if debug_level > 0:
            print "cmd_output: "
            print ssh_output
        count += 1

    if not bigip_active:
        sys.exit("\nUnable to access new BIG-IP instance.  Ensure that instance is running and accessible. Exiting...")

    # SSH to configured new BIG-IP with previously saved hostname
    cmd_str = "modify sys global-settings hostname " + hostname
    ssh_output = ssh_cmd(  
                            user=username, 
                            ssh_key=ssh_key, 
                            host=management_ip, 
                            cmd_str=cmd_str,
                            debug=debug_level,
                            timeout=30, 
                            host_key_check=False, 
                            bg_run=False
                        ) 
    if debug_level > 0:
        print "cmd_output: "
        print ssh_output

    # Confirm Hostname:
    cmd_str = "list sys global-settings hostname"
    ssh_output = ssh_cmd(  
                            user=username, 
                            ssh_key=ssh_key, 
                            host=management_ip, 
                            cmd_str=cmd_str,
                            debug=debug_level,
                            timeout=30, 
                            host_key_check=False, 
                            bg_run=False
                        ) 
    if debug_level > 0:
        print "cmd_output: "
        print ssh_output

    match = re.search('hostname (.+)', ssh_output)
    dst_hostname = match.group(1)
    print "Destination hostname is " + dst_hostname

    if hostname == dst_hostname:
        print "Hostname set successful."

    # Check if destination image is BYOL then license via CLI else do not overwrite license of HB
    if not dest_image_hourly: 
        # License via CLI.  
        # Assumes User called and did an "Allow Move"
        regkey_string = ","
        cmd_str = "install sys license registration-key " + regkey_string.join(regkey_list)
        ssh_output = ssh_cmd(  
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

        print "Waiting 30 seconds for mcpd to restart...Please wait..."
        time.sleep(30)

    if cve: # Upload clean ucs and md5 and restore-clean-ucs script to BIG-IP
        # scp f5-<instanceid>-clean.ucs from local to /var/local/ucs on BIG-IP
        remote_file = "/var/local/ucs/clean.ucs"
        local_file = 'f5-' + src_instance_id + "-clean.ucs"
        scp_output = scp_upload_cmd (
                                        user=username, 
                                        ssh_key=ssh_key, 
                                        host=management_ip, 
                                        remote_file=remote_file,
                                        local_file=local_file,  
                                        timeout=30, 
                                        host_key_check=False, 
                                        bg_run=False
                                      ) 
        if debug_level > 0:
            print "scp_output: "
            print scp_output

        # scp f5-<instanceid>-clean.ucs.md5 from local to /var/local/ucs on BIG-IP
        remote_file_md5sum = remote_file + ".md5"
        local_file_md5sum = local_file + ".md5"
        upload_check_md5sum_file(username, ssh_key, management_ip, local_file_md5sum, remote_file_md5sum, debug_level)

        # scp and run restore-clean-ucs in /tmp on BIG-IP    
        remote_restore_clean_ucs_file = "/tmp/restore-clean-ucs"
        local_restore_clean_ucs_file = "restore-clean-ucs"
        scp_output = scp_upload_cmd (
                                        user=username, 
                                        ssh_key=ssh_key, 
                                        host=management_ip, 
                                        remote_file=remote_restore_clean_ucs_file,
                                        local_file=local_restore_clean_ucs_file,  
                                        timeout=30, 
                                        host_key_check=False, 
                                        bg_run=False
                                      ) 
        if debug_level > 0:
            print "scp_output: "
            print scp_output

        # Get masterkey1 to pass to restore-clean-ucs
        with open(cached_masterkey1_filename) as masterkey1_file:
            masterkey1 = masterkey1_file.read()

        print "Masterkey from file = " + masterkey1
        # Run restore-clean-ucs in /tmp on BIG-IP
        pexpect_restore_clean_ucs ( username, ssh_key, password, management_ip, masterkey1, debug_level )
    else: # Non-CVE
        # # Upload UCS (CLI/Bigsuds?) 
        # Create Backup UCS with New License?
        local_file = "f5-" + src_instance_id + ".ucs"
        remote_file = "/var/local/ucs/" + local_file
        cmd_str = "save /sys ucs /var/tmp/f5-pre-restore-" + src_instance_id + ".ucs"
        ssh_output = ssh_cmd(
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

        # Upload UCS file
        scp_output = scp_upload_cmd (
                                        user=username, 
                                        ssh_key=ssh_key, 
                                        host=management_ip, 
                                        remote_file=remote_file,
                                        local_file=local_file,  
                                        timeout=30, 
                                        host_key_check=False, 
                                        bg_run=False
                                      ) 
        if debug_level > 0:
            print "scp_output: "
            print scp_output

        local_file_md5sum = local_file + ".md5"
        remote_file_md5sum = remote_file + ".md5"
        upload_check_md5sum_file(username, ssh_key, management_ip, local_file_md5sum, remote_file_md5sum, debug_level)

        # # Install UCS
        #load sys ucs /var/tmp/old-config.ucs no-license
        cmd_str = "run util bash -c 'tmsh load sys ucs " + remote_file + " no-license'"
        ssh_output = ssh_cmd(  
                                user=username, 
                                ssh_key=ssh_key, 
                                host=management_ip, 
                                cmd_str=cmd_str,
                                debug=debug_level,
                                timeout=30, 
                                host_key_check=False, 
                                bg_run=False
                            ) 
        if debug_level > 0:
            print "cmd_output: "
            print ssh_output

    print "_____BIG-IP Migration Completed_____\n"

if __name__ == "__main__":
    main()