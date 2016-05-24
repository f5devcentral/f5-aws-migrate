# Introduction
f5-aws-migrate.py is a Python 2.7 script that automates the migration of a BIG-IP instance to another instance in AWS for the two types of BIG-IP images available on the AWS Marketplace. The script begins by gathering a BIG-IP UCS (User Configuration Set; a backup) file and polling AWS to gather instance configuration details. It then terminates the original instance and launches a new, identical instance using the AMI image you specify. Finally, the script performs automated licensing and installs the UCS file from the original instance with a no-license flag to avoid overwriting the new license. The script can also perform complete BIG-IP mitigation steps for [CVE-2016-2084](https://support.f5.com/kb/en-us/solutions/public/k/11/sol11772107.html).

    * Type 1 – Utility (Hourly/Annual Subscriptions)
    * Type 2 – BYOL (Bring Your Own License)

F5 DevCentral Article - [F5 BIG-IP Instance Migration in AWS](https://devcentral.f5.com/articles/f5-big-ip-instance-migration-in-aws-19992)

## Key capabilities
1. Automates BIG-IP instance migration in AWS for the following scenarios:
    * Utility to Utility (Do not need registration key)
    * Utility to BYOL (Must have new BYOL registration key)
    * BYOL to BYOL (Must contact F5 Support to request an Allow Move on registration key)
    * BYOL to Utility (Do not need registration key)
2. Automates complete BIG-IP mitigation steps for [CVE-2016-2084](https://support.f5.com/kb/en-us/solutions/public/k/11/sol11772107.html) by running the script in CVE mode using -C or --CVE flags. Auto-generate masterkey1 required by BASH scripts save-clean-ucs and restore-clean-ucs.  Auto-generate masterkey2 required by restore-clean-ucs script.
    * SOL 11772107: BIG-IP and BIG-IQ cloud image vulnerability CVE-2016-2084 (https://support.f5.com/kb/en-us/solutions/public/k/11/sol11772107.html)
3. Allows re-running of the automated script on a previously selected AWS BIG-IP instance.


The script will:

1. Log on to BIG-IP (via SSH, iControl), gather a UCS
2. Poll AWS to gather Source AMI's network interfaces
3. Sets ENIs DeleteOnTermination to False so can simply re-use 
4. Terminates Source AMI Instance (so can detach ENIs)
5. Launch New AMI Instance with ENI Ids from Source AMI Instance above
6. Install License (from Regkey from Source AMI Instance or Option ) for BYOL
7. Install UCS (with no-license flag to not overwrite new license )

* **All scripts need to be downloaded and run on a remote host (not on the BIG-IP instance) with the following requirements.**

# Requirements
1. SSH and SCP access from the remote host to the management interface of the BIG-IP instance.
2. Python 2.7 environment
    * https://www.python.org/download/releases/2.7/
2. AWS CLI (for testing and troubleshooting)
    * https://aws.amazon.com/cli/ 
3. BOTO3 (Required to run script)
    * https://boto3.readthedocs.org/en/latest/
4. Pexpect (Required to run script in CVE mode using -C or --CVE flags)
    * https://pexpect.readthedocs.org/en/stable/
2. Python script f5-aws-migrate.py 
    * Git Repository https://github.com/f5devcentral/f5-aws-migrate
5. BASH scripts save-clean-ucs and restore-clean-ucs from [CVE-2016-2084](https://support.f5.com/kb/en-us/solutions/public/k/11/sol11772107.html) (Required for CVE runs).
    * **Both BASH scripts are included with f5-aws-migrate.py in above [git repository](https://github.com/f5devcentral/f5-aws-migrate).**

# Installation
Download the script(s) and README files from https://github.com/f5devcentral/f5-aws-migrate.  Install on the remote host.

# Examples of running the script f5-aws-migrate.py
For help:
```sh
$ python f5-aws-migrate.py -h
Usage: f5-aws-migrate.py [options]

Options:
  -h, --help            show this help message and exit
  -f, --force           Force Migration
  -C, --CVE             cve-2016-2084-remediation
  -k SSH_KEY, --ssh-key=SSH_KEY
                        SSH Key File - full path
  -i SRC_INSTANCE_ID, --src-instance-id=SRC_INSTANCE_ID
                        Source Big-IP instance-id
  -m MANAGEMENT_IP, --management-ip=MANAGEMENT_IP
                        Management Ip
  -u USERNAME, --username=USERNAME
                        Big-IP admin username
  -p PASSWORD, --password=PASSWORD
                        Big-IP admin password
  -d DEST_AMI, --dest-ami=DEST_AMI
                        Destination Big-IP AMI
  -t DEST_INSTANCE_TYPE, --dest-instance-type=DEST_INSTANCE_TYPE
                        Destination Instance Type
  -r REGKEYS, --regkeys=REGKEYS
                        Comma seperated list of regkeys
  -R AWS_REGION, --aws-region=AWS_REGION
                        AWS Region
  -A AWS_ACCESS_KEY, --aws-access-key=AWS_ACCESS_KEY
                        AWS Access Key
  -S AWS_SECRET_KEY, --aws-secret-key=AWS_SECRET_KEY
                        AWS Secret Key
  --debug-level=DEBUG_LEVEL
                        debug level print debug (0-9)
```
## All Examples
Local username john has AWS key pair file VE-DEMO.pem stored in his home directory /home/john/.ssh/VE-DEMO.pem. AWS config and credentials files stored in his home directory /Users/john/.aws. Running migration script with debug level 1 with more output. Default default level is 0.

```sh
john$ pwd
/Users/john/.aws
john$ ls
config credentials
john$ more config
[default]
region = us-west-2
john$ more credentials
[default]
aws_access_key_id = APOPJOYHFXYCWHKZDJ3Q
aws_secret_access_key = MYsVrwik4ArWSvhgitcqUu6CIDG+Fvg2D5jp9aJ5
```

## Classic Migration Examples
Utility instance to a new Utility instance (Do not need registration key)
```sh
$ python f5-aws-migrate.py -k /home/john/.ssh/VE-DEMO.pem -i i-155b46d2 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-d9ee1ab9 -R us-west-2 --debug-level 1
```
BYOL instance to a new BYOL instance (Must contact F5 Support to request an Allow Move on registration key)
```sh
$ python f5-aws-migrate.py -k /home/john/.ssh/VE-DEMO.pem -i i-f75d4030 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-5fe81c3f -R us-west-2 --debug-level 1
```
Utility instance to a new BYOL instance (Must have new BYOL registration key)
```sh
$ python f5-aws-migrate.py -k /home/john/.ssh/VE-DEMO.pem -i i-155b46d2 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-5fe81c3f -r ZJQWC-EXJMJ-HEKVX-KNJTB-LGUCGVZ -R us-west-2 --debug-level 1
```
BYOL instance to a new Utility instance (Do not need registration key)
```sh
$ python f5-aws-migrate.py -k /home/john/.ssh/VE-DEMO.pem -i i-f75d4030 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-d9ee1ab9 -R us-west-2 --debug-level 1
```
## CVE Migration Examples
Utility instance to a new Utility instance (Do not need registration key)
```sh
$ python f5-aws-migrate.py -C -k /home/john/.ssh/VE-DEMO.pem -i i-e0880167 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-d9ee1ab9 -R us-west-2 --debug-level 1
```
BYOL instance to a new BYOL instance (Must contact F5 Support to request an Allow Move on registration key)
```sh
$ python f5-aws-migrate.py -C -k /home/john/.ssh/VE-DEMO.pem -i i-e45d4023 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-5fe81c3f -R us-west-2 --debug-level 1
```
Utility instance to a new BYOL instance (Must have new BYOL registration key)
```sh
$ python f5-aws-migrate.py -C -k /home/john/.ssh/VE-DEMO.pem -i i-e0880167 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-5fe81c3f -r ZJQWC-EXJMJ-HEKVX-KNJTB-LGUCGVZ -R us-west-2 --debug-level 1
```
BYOL instance to a new Utility instance (Do not need registration key)
```sh
$ python f5-aws-migrate.py -C -k /home/john/.ssh/VE-DEMO.pem -i i-e45d4023 -m 10.0.0.245 -u admin -p ‘strongpassword’ -d ami-d9ee1ab9 -R us-west-2 --debug-level 1
```
