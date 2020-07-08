import ssl
import sys
import json
import os
import urllib3
import requests
import toml
import atexit
import re
import traceback
from dateutil.parser import isoparse
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl


# GLOBAL_VARS
DEBUG=False
# CONFIG
VC_CONFIG='/var/openfaas/secrets/vcconfig'
VRO_CONFIG='/var/openfaas/secrets/vroconfig'
service_instance = None
vrohost = None
vrouser = None
vropass = None

class bgc:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

if(os.getenv("write_debug")):
    sys.stderr.write(f"{bgc.WARNING}WARNING!! DEBUG has been enabled for this function. Sensitive information could be printed to sysout{bgc.ENDC} \n")
    DEBUG=True

def debug(s):
    if DEBUG:
        sys.stderr.write(s+" \n") #Syserr only get logged on the console logs
        sys.stderr.flush()
        
def init():
    """
    Load the config and set up a connection to vc
    """
    global service_instance,vchost,vrohost,vrouser,vropass
    
    # Load the Config File
    debug(f'{bgc.HEADER}Reading Configuration files: {bgc.ENDC}')
    debug(f'{bgc.OKBLUE}VC Config File > {bgc.ENDC}{VC_CONFIG}')
    try:
        with open(VC_CONFIG, 'r') as vcconfigfile:
				        vcconfig = toml.load(vcconfigfile)
				        vchost=vcconfig['vcenter']['server']
				        vcuser=vcconfig['vcenter']['user']
				        vcpass=vcconfig['vcenter']['pass']
    except OSError as err:
        return 'Could not read vcenter configuration: {0}'.format(err), 500
    except KeyError as err:
        return 'Mandatory configuration key not found: {0}'.format(err), 500
    
    debug(f'{bgc.OKBLUE}VRO Config File > {bgc.ENDC}{VRO_CONFIG}')
    try:
        with open(VRO_CONFIG, 'r') as vroconfigfile:
				        vroconfig = toml.load(vroconfigfile)
				        vrohost=vroconfig['vro']['server']
				        vrouser=vroconfig['vro']['user']
				        vropass=vroconfig['vro']['pass']
    except OSError as err:
        return 'Could not read vro configuration: {0}'.format(err), 500
    except KeyError as err:
        return 'Mandatory configuration key not found: {0}'.format(err), 500
        
    debug(f'vrohost: {vrohost}')
    
    sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    if(os.getenv("insecure_ssl")):
        sslContext.verify_mode = ssl.CERT_NONE
    
    debug(f'{bgc.OKBLUE}Initialising vCenter connection{bgc.ENDC}')
    try:
        service_instance = connect.SmartConnect(host=vchost,
                                        user=vcuser,
                                        pwd=vcpass,
                                        port=443,
                                        sslContext=sslContext)
        atexit.register(connect.Disconnect, service_instance)
    except IOError as err:
        return 'Error connecting to vCenter: {0}'.format(err), 500

    if not service_instance:
        return 'Unable to connect to vCenter host with supplied credentials', 400
        
        
def getManagedObject(obj):
    """
    Convert an object as received from the event router in to a pyvmomi managed object
    Args:
        obj (object): object received from the event router
    """
    mo = None
    try:
        moref = obj['Value']
        type = obj['Type']
    except KeyError as err:
        traceback.print_exc(limit=1, file=sys.stderr) #providing traceback since it helps debug the exact key that failed
        return 'Invalid JSON, required key not found > KeyError: {0}'.format(err), 400
        
    if hasattr(vim, type):
        typeMethod = getattr(vim, type)
        mo = typeMethod(moref)
        mo._stub = service_instance._stub
        try:
            debug(f'{bgc.OKBLUE}Managed object > {bgc.ENDC}{moref} has name {mo.name} and type {mo.__class__.__name__.rpartition(".")[2]}')
            return mo
        except vmodl.fault.ManagedObjectNotFound as err:
            debug(f'{bgc.FAIL}{err.msg}{bgc.ENDC}')
    return None
    

def getViObjectPath(obj):
    """
    Gets the full path to the passed managed object
    Args:
        obj (vim.ManagedObject): VC managed object
    """
    path = ""
    while obj != service_instance.content.rootFolder:
        path = f'/{obj.name}{path}'
        obj = obj.parent
    return path


def filterVcObject(obj, filter):
    """
    Takes a VC managed object and tests it against a filter
    If it matches, a vRO input parameter object is returned
    Args:
        obj (vim.ManagedObject): VC managed Object
        filter (str): Regex filter string
    """

    if obj:
        mo_type = obj.__class__.__name__.rpartition(".")[2]
        res = {
            "type": mo_type,
            "name": mo_type,
            "scope": "local",
            "value": {
                "sdk-object": {
                    "type": mo_type,
                    "id": f'{vchost},id:{obj._moId}'
                }
            }
        }
        if filter:
            debug(f'{bgc.OKBLUE}{mo_type} Filter > {bgc.ENDC}{filter}')
            objPath = getViObjectPath(obj)
            debug(f'{bgc.OKBLUE}{mo_type} Path > {bgc.ENDC}{objPath}')
            if not re.search(filter, objPath):
                debug(f'{bgc.WARNING}Filter "{filter}" does not match {mo_type} path "{objPath}". Exiting{bgc.ENDC}')
                res = f'Filter "{filter}" does not match {mo_type} path "{objPath}"', 200
            else:
                debug(f'{bgc.OKBLUE}Match > {bgc.ENDC}Filter matched {mo_type} path')
        return res


def getVroInputParam(item):
    """
    Takes an object from the event router data and turns it in to a vRO input parameter
    Args:
        item (tuple): event router event data parameter name, value pair
    """
    name, value = item
    #debug(f'Event key "{name}" -> type "{type(value).__name__}"')
    param = {
        "scope": "local"
    }
    # Determin the data type of the object and create a vRO input parameter
    if type(value) == int:
        param['type'] = "number"
        param['value'] = {"number": {"value": value }}

    elif isinstance(value, str): 
        try: # for strings, try and parse to a date first...
            d = isoparse(value)
            param['type'] = "Date"
            param['value'] = {"date": {"value": value }}
        except: # ...if that doesn't work just build a string
            param['type'] = "string"
            param['value'] = {"string": {"value": value }}

    elif type(value) == bool:
        param['type'] = "boolean"
        param['value'] = {"boolean": {"value": value }}

    elif type(value) == dict: # a dict is probably a VC manged object reference
        for k, v in value.items():
            # search the items of the dict and look for contained dicts with a 'Type' property
            if type(v) == dict and 'Type' in v:
                objFilter = eval(f'os.getenv("filter_{name.lower()}", default=".*")')
                mo = getManagedObject(v)
                param = filterVcObject(mo, objFilter)
    
    elif type(value) == list:
        param['type'] = "Properties"
        properties = []
        for v in value:
            if 'Key' in v and 'Value' in v:
                #pass the key and value to this function recursively to get a correctly structured value
                properties.append({"key": v["Key"], "value": getVroInputParam((v["Key"],v["Value"]))["value"]})
        param['value'] = {"properties": {"property": properties}}
        
    elif value == None:
        param = None
        
    else: #Unhandled data type - try and wrangle to a string
        debug(f'{bgc.WARNING}Unhandled data type "{type(value).__name__}" - forcing to string{bgc.ENDC}')
        param['type'] = "string"
        param['value'] = {"string": {"value": str(value) }}
        
    if type(param) == dict: #set the parameter name for valid types
        param["name"] = name[0].lower() + name[1:]
    return param


def handle(req):
    """
    Handle a request to the function
    Args:
        req (str): request body
    """

    if(os.getenv("insecure_ssl")):
        # Surpress SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Initialise a connection to vCenter if required
    try:
        vcinfo = service_instance.content.about
        debug(f'Connected to {vcinfo.fullName} ({vcinfo.instanceUuid})')
    except:
        debug(f'{bgc.WARNING}Init VC Connection...{bgc.ENDC}')
        res = init()
        if isinstance(res, tuple): #Error state
            return res
        vcinfo = service_instance.content.about
    
    # Load the Events that function gets from vCenter through the Event Router
    debug(f'{bgc.HEADER}Reading Cloud Event: {bgc.ENDC}')
    debug(f'{bgc.OKBLUE}Event > {bgc.ENDC}{req}')
    try:
        cevent = json.loads(req)
    except json.JSONDecodeError as err:
        return 'Invalid JSON > JSONDecodeError: {0}'.format(err), 400
    
    debug(f'{bgc.HEADER}Validating Input data: {bgc.ENDC}')
    debug(f'{bgc.OKBLUE}Event > {bgc.ENDC}{json.dumps(cevent, indent=4, sort_keys=True)}')
    try:
        #CloudEvent - simple validation
        event = cevent['data']
        event_items = event.items()
    except KeyError as err:
        traceback.print_exc(limit=1, file=sys.stderr) #providing traceback since it helps debug the exact key that failed
        return 'Invalid JSON, required key not found > KeyError: {0}'.format(err), 400
    except AttributeError as err:
        traceback.print_exc(limit=1, file=sys.stderr) #providing traceback since it helps debug the exact key that failed
        return 'Invalid JSON, data not iterable > AttributeError: {0}'.format(err), 400
    
    debug(f'{bgc.HEADER}All tests passed! Build vRO request:{bgc.ENDC}')
    #Build the vRO input parameter object ysung the event parameters
    body = {"parameters": []}
    for item in event.items():
        # Get the vRO input parameter correctly formatted for the received event data
        # Filtering is also performed here
        res = getVroInputParam(item)
        if res:
            if isinstance(res, tuple): # Tuple (rather than dict) is returned if the object didn't match the filter
                #log.append({'INFO': res[0]})
                return json.dumps(log, indent=4), res[1]
            # Append the vRO parameter to the body
            body["parameters"].append(res)
    body["parameters"].append(getVroInputParam(("rawEventData", json.dumps(cevent))))
    #debug(f'REST body: {json.dumps(body, indent=4)}')
    
    if DEBUG:
        debug(f'{bgc.HEADER}Passing the following params to vRO:{bgc.ENDC}')
        for p in body["parameters"]:
            debug(f'Param: {p["name"]} - Type: {p["type"]}')
    
    wfId = os.getenv("vro_workflow_id")
    debug(f'Workflow ID: {wfId}')
    
    vroUrl = f'https://{vrohost}:443/vco/api/workflows/{wfId}/executions'
    
    debug(f'{bgc.HEADER}Attemping HTTP POST: {bgc.ENDC}')
    try:
        #POST to vRO REST API
        r = requests.post(vroUrl, 
                      auth=(vrouser, vropass), 
                      json=body,
                      verify=not os.getenv("insecure_ssl")
                  )
    except Exception as err:
        traceback.print_exc(limit=1, file=sys.stderr) #providing traceback since it helps debug the exact key that failed
        return 'Unexpected error occurred > Exception: {0}'.format(err), 500
    
    debug(f'{bgc.OKBLUE}POST Successful...{bgc.ENDC}')
    try:
        vro_res = json.loads(r.text)
    except json.decoder.JSONDecodeError as err:
        traceback.print_exc(limit=1, file=sys.stderr) #providing traceback since it helps debug the exact key that failed
        return f'Response is not valid JSON\n{r.text}', r.status_code
    
    #debug(f'{bgc.OKBLUE}vRO Response: {bgc.ENDC}')
    #debug(json.dumps(vro_res))
    
    debug(f'Successfully executed vRO workflow: {vro_res["name"]}')
    return r.text, r.status_code


#
## Unit Test - helps testing the function locally
## Uncomment r=handle('...') to test the function with the event samples provided below test without deploying to OpenFaaS
#
if __name__ == '__main__':
    VRO_CONFIG='vro-secrets.toml'
    VC_CONFIG='vc-secrets.toml'
    DEBUG=True
    os.environ['insecure_ssl'] = 'true'
    os.environ['filter_vm'] = '/Pilue/vm/Infrastructure/.*'
    os.environ['vro_workflow_id'] = '2205ea6c-7b24-4389-b36d-1188c537d44d'
    #
    ## FAILURE CASES :Invalid Inputs
    #
    #r=handle('')
    #r=handle('"test":"ok"')
    #r=handle('{"test":"ok"}')
    #r=handle('{"data":"ok"}')

    #
    ## SUCCESS CASES :Invalid vc objects
    #
    #r=handle('{"id":"c7a6c420-f25d-4e6d-95b5-e273202e1164","source":"https://vcsa01.lab/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DrsVmPoweredOnEvent","time":"2020-07-02T15:16:13.533866543Z","data":{"Key":130278,"ChainId":130273,"CreatedTime":"2020-07-02T15:16:11.213467Z","UserName":"Administrator","Datacenter":{"Name":"Lab","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":{"Name":"Lab","ComputeResource":{"Type":"ClusterComputeResource","Value":"domain-c47"}},"Host":{"Name":"esxi03.lab","Host":{"Type":"HostSystem","Value":"host-9999"}},"Vm":{"Name":"Bad VM","Vm":{"Type":"VirtualMachine","Value":"vm-9999"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"DRS powered on Bad VM on esxi01.lab in Lab","ChangeTag":"","Template":false},"datacontenttype":"application/json"}')
    
    #
    ## SUCCESS CASES
    # 
    # Standard : UserLogoutSessionEvent
    #r=handle('{"id":"17e1027a-c865-4354-9c21-e8da3df4bff9","source":"https://vcsa.pdotk.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"UserLogoutSessionEvent","time":"2020-04-14T00:28:36.455112549Z","data":{"Key":7775,"ChainId":7775,"CreatedTime":"2020-04-14T00:28:35.221698Z","UserName":"machine-b8eb9a7f","Datacenter":null,"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"User machine-b8ebe7eb9a7f@127.0.0.1 logged out (login time: Tuesday, 14 April, 2020 12:28:35 AM, number of API invocations: 34, user agent: pyvmomi Python/3.7.5 (Linux; 4.19.84-1.ph3; x86_64))","ChangeTag":"","IpAddress":"127.0.0.1","UserAgent":"pyvmomi Python/3.7.5 (Linux; 4.19.84-1.ph3; x86_64)","CallCount":34,"SessionId":"52edf160927","LoginTime":"2020-04-14T00:28:35.071817Z"},"datacontenttype":"application/json"}')
    # Eventex : vim.event.ResourceExhaustionStatusChangedEvent
    #r=handle('{"id":"0707d7e0-269f-42e7-ae1c-18458ecabf3d","source":"https://vcsa.pdotk.local/sdk","specversion":"1.0","type":"com.vmware.event.router/eventex","subject":"vim.event.ResourceExhaustionStatusChangedEvent","time":"2020-04-14T00:20:15.100325334Z","data":{"Key":7715,"ChainId":7715,"CreatedTime":"2020-04-14T00:20:13.76967Z","UserName":"machine-bb9a7f","Datacenter":null,"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"vCenter Log File System Resource status changed from Yellow to Green on vcsa.pdotk.local  ","ChangeTag":"","EventTypeId":"vim.event.ResourceExhaustionStatusChangedEvent","Severity":"info","Message":"","Arguments":[{"Key":"resourceName","Value":"storage_util_filesystem_log"},{"Key":"oldStatus","Value":"yellow"},{"Key":"newStatus","Value":"green"},{"Key":"reason","Value":" "},{"Key":"nodeType","Value":"vcenter"},{"Key":"_sourcehost_","Value":"vcsa.pdotk.local"}],"ObjectId":"","ObjectType":"","ObjectName":"","Fault":null},"datacontenttype":"application/json"}')
    # Standard : DrsVmPoweredOnEvent
    r=handle('{"id":"c7a6c420-f25d-4e6d-95b5-e273202e1164","source":"https://vcsa01.lab.core.pilue.co.uk/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DrsVmPoweredOnEvent","time":"2020-07-02T15:16:13.533866543Z","data":{"Key":130278,"ChainId":130273,"CreatedTime":"2020-07-02T15:16:11.213467Z","UserName":"Administrator","Datacenter":{"Name":"Pilue","Datacenter":{"Type":"Datacenter","Value":"datacenter-9"}},"ComputeResource":{"Name":"Lab","ComputeResource":{"Type":"ClusterComputeResource","Value":"domain-c47"}},"Host":{"Name":"esxi03.lab.core.pilue.co.uk","Host":{"Type":"HostSystem","Value":"host-3523"}},"Vm":{"Name":"sexigraf","Vm":{"Type":"VirtualMachine","Value":"vm-82"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"DRS powered on sexigraf on esxi03.lab.core.pilue.co.uk in Pilue","ChangeTag":"","Template":false},"datacontenttype":"application/json"}')
    # Standard : VmPoweredOffEvent
    #r=handle('{"id":"d77a3767-1727-49a3-ac33-ddbdef294150","source":"https://vcsa.pdotk.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"VmPoweredOffEvent","time":"2020-04-14T00:33:30.838669841Z","data":{"Key":7825,"ChainId":7821,"CreatedTime":"2020-04-14T00:33:30.252792Z","UserName":"Administrator","Datacenter":{"Name":"PKLAB","Datacenter":{"Type":"Datacenter","Value":"datacenter-3"}},"ComputeResource":{"Name":"esxi01.pdotk.local","ComputeResource":{"Type":"ComputeResource","Value":"domain-s29"}},"Host":{"Name":"esxi01.pdotk.local","Host":{"Type":"HostSystem","Value":"host-31"}},"Vm":{"Name":"Test VM","Vm":{"Type":"VirtualMachine","Value":"vm-33"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"Test VM on  esxi01.pdotk.local in PKLAB is powered off","ChangeTag":"","Template":false},"datacontenttype":"application/json"}')
    # Standard : DvsPortLinkUpEvent
    #r=handle('{"id":"a10f8571-fc2a-40db-8df6-8284cecf5720","source":"https://vcsa01.lab.core.pilue.co.uk/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DvsPortLinkUpEvent","time":"2020-07-02T15:16:13.43892986Z","data":{"Key":130277,"ChainId":130277,"CreatedTime":"2020-07-02T15:16:11.207727Z","UserName":"","Datacenter":{"Name":"Pilue","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":{"Name":"Lab Switch","Dvs":{"Type":"VmwareDistributedVirtualSwitch","Value":"dvs-22"}},"FullFormattedMessage":"The dvPort 2 link was up in the vSphere Distributed Switch Lab Switch in Pilue","ChangeTag":"","PortKey":"2","RuntimeInfo":null},"datacontenttype":"application/json"}')
    # Standard : DatastoreRenamedEvent
    #r=handle('{"id":"369b403a-6729-4b0b-893e-01383c8307ba","source":"https://vcsa01.lab.core.pilue.co.uk/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DatastoreRenamedEvent","time":"2020-07-02T21:44:11.09338265Z","data":{"Key":130669,"ChainId":130669,"CreatedTime":"2020-07-02T21:44:08.578289Z","UserName":"","Datacenter":{"Name":"Pilue","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"Renamed datastore from esxi04-local to esxi04-localZ in Pilue","ChangeTag":"","Datastore":{"Name":"esxi04-localZ","Datastore":{"Type":"Datastore","Value":"datastore-3313"}},"OldName":"esxi04-local","NewName":"esxi04-localZ"},"datacontenttype":"application/json"}')
    # Standard : DVPortgroupRenamedEvent
    #r=handle('{"id":"aab77fd1-41ed-4b51-89d3-ef3924b09de1","source":"https://vcsa01.lab.core.pilue.co.uk/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DVPortgroupRenamedEvent","time":"2020-07-03T19:36:38.474640186Z","data":{"Key":132376,"ChainId":132375,"CreatedTime":"2020-07-03T19:36:32.525906Z","UserName":"Administrator","Datacenter":{"Name":"Pilue","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":{"Name":"vMotion AZ","Network":{"Type":"DistributedVirtualPortgroup","Value":"dvportgroup-3357"}},"Dvs":{"Name":"10G Switch A","Dvs":{"Type":"VmwareDistributedVirtualSwitch","Value":"dvs-3355"}},"FullFormattedMessage":"dvPort group vMotion A in Pilue was renamed to vMotion AZ","ChangeTag":"","OldName":"vMotion A","NewName":"vMotion AZ"},"datacontenttype":"application/json"}')
   
    print(f'Status code: {r[1]}')
    #print(r[0])