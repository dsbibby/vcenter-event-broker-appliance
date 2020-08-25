import sys
import json
import os
import urllib3
import requests
import toml
import traceback
from dateutil.parser import isoparse


# GLOBAL_VARS
DEBUG = False
# CONFIG
VRO_CONFIG = '/var/openfaas/secrets/vroconfig'
vchost = None


class bgc:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if os.getenv("write_debug"):
    sys.stderr.write(f"{bgc.WARNING}WARNING!! DEBUG has been enabled for this function. Sensitive information could be printed to sysout{bgc.ENDC} \n")
    DEBUG = True


def debug(s):
    if DEBUG:
        sys.stderr.write(s + " \n")  # Syserr only get logged on the console logs
        sys.stderr.flush()


def getVroInputParam(item):
    """
    Takes an object from the event router data and turns it in to a vRO input parameter
    Args:
        item (tuple): event router event data parameter name, value pair
    """
    name, value = item
    # debug(f'Event key "{name}" -> type "{type(value).__name__}"')
    param = {
        "scope": "local"
    }
    # Determin the data type of the object and create a vRO input parameter
    if type(value) == int:
        param['type'] = "number"
        param['value'] = {"number": {"value": value}}

    elif isinstance(value, str):
        try:  # for strings, try and parse to a date first...
            isoparse(value)
            param['type'] = "Date"
            param['value'] = {"date": {"value": value}}
        except ValueError:  # ...if that doesn't work just build a string
            param['type'] = "string"
            param['value'] = {"string": {"value": value}}

    elif type(value) == bool:
        param['type'] = "boolean"
        param['value'] = {"boolean": {"value": value}}

    elif type(value) == dict:  # a dict is likely a VC manged object reference
        for v in value.values():
            # search the items of the dict and look for contained dicts with a 'Type' property
            if type(v) == dict and 'Type' in v:
                param['type'] = f"VC:{v['Type']}"
                param['value'] = {
                    "sdk-object": {
                        "type": param['type'],
                        "id": f'{vchost},id:{v["Value"]}'
                    }
                }
        if not 'type' in param: # if no vc managed object was found, pass the data as JSON
            param['type'] = 'string'
            param['value'] = {"string": {"value": json.dumps(value)}}

    elif type(value) == list:
        param['type'] = "Properties"
        properties = []
        for v in value:
            if 'Key' in v and 'Value' in v:
                # pass the key and value to this function recursively to get a correctly structured value
                vroParam = getVroInputParam((v["Key"], v["Value"]))
                properties.append({"key": v["Key"], "value": vroParam["value"]})
        param['value'] = {"properties": {"property": properties}}

    elif value is None:
        param = None

    else:  # Unhandled data type - try and wrangle to a string
        debug(f'{bgc.WARNING}Unhandled data type "{type(value).__name__}" - forcing to string{bgc.ENDC}')
        param['type'] = "string"
        param['value'] = {"string": {"value": str(value)}}

    if type(param) == dict:  # set the parameter name for valid types
        param["name"] = name[0].lower() + name[1:]
    return param


def handle(req):
    """
    Handle a request to the function
    Args:
        req (str): request body
    """
    global vchost

    if(os.getenv("insecure_ssl")):
        # Surpress SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    debug(f'{bgc.OKBLUE}VRO Config File > {bgc.ENDC}{VRO_CONFIG}')
    try:
        with open(VRO_CONFIG, 'r') as vroconfigfile:
            vroconfig = toml.load(vroconfigfile)
            vrohost = vroconfig['vro']['server']
            vroport = vroconfig['vro']['port']
            vrouser = vroconfig['vro']['user']
            vropass = vroconfig['vro']['pass']
    except OSError as err:
        return 'Could not read vro configuration: {0}'.format(err), 500
    except KeyError as err:
        return 'Mandatory configuration key not found: {0}'.format(err), 500

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
        # CloudEvent - simple validation
        source = cevent['source']
        event = cevent['data']
    except KeyError as err:
        traceback.print_exc(limit=1, file=sys.stderr)  # providing traceback since it helps debug the exact key that failed
        return 'Invalid JSON, required key not found > KeyError: {0}'.format(err), 400
    except AttributeError as err:
        traceback.print_exc(limit=1, file=sys.stderr)  # providing traceback since it helps debug the exact key that failed
        return 'Invalid JSON, data not iterable > AttributeError: {0}'.format(err), 400

    vchost = urllib3.util.url.parse_url(source).host
    debug(f'{bgc.HEADER}All tests passed! Build vRO request:{bgc.ENDC}')
    # Build the vRO input parameter object using the event parameters
    body = {"parameters": []}
    for item in event.items():
        # Get the vRO input parameter correctly formatted for the received event data
        res = getVroInputParam(item)
        if res:
            body["parameters"].append(res)
    body["parameters"].append(getVroInputParam(("rawEventData", json.dumps(cevent))))
    debug(f'REST body: {json.dumps(body, indent=4)}')

    if DEBUG:
        debug(f'{bgc.HEADER}Passing the following params to vRO:{bgc.ENDC}')
        for p in body["parameters"]:
            debug(f'Param: {p["name"]} - Type: {p["type"]}')

    wfId = os.getenv("vro_workflow_id")
    debug(f'Workflow ID: {wfId}')

    vroUrl = f'https://{vrohost}:{vroport}/vco/api/workflows/{wfId}/executions'

    debug(f'{bgc.HEADER}Attemping HTTP POST: {bgc.ENDC}')
    try:
        # POST to vRO REST API
        r = requests.post(vroUrl,
                          auth=(vrouser.encode('utf-8'), vropass.encode('utf-8')),
                          json=body,
                          verify=not os.getenv("insecure_ssl")
                          )
    except Exception as err:
        traceback.print_exc(limit=1, file=sys.stderr)  # providing traceback since it helps debug the exact key that failed
        return 'Unexpected error occurred > Exception: {0}'.format(err), 500

    debug(f'{bgc.OKBLUE}POST Successful...{bgc.ENDC}')

    if r.ok:
        try:
            vro_res = json.loads(r.text)
        except json.decoder.JSONDecodeError:
            traceback.print_exc(limit=1, file=sys.stderr)  # providing traceback since it helps debug the exact key that failed
            return f'Response is not valid JSON\n{r.text}', r.status_code

        debug(f'Successfully executed vRO workflow: {vro_res["name"]}')

        # debug(f'{bgc.OKBLUE}vRO Response: {bgc.ENDC}')
        # debug(json.dumps(vro_res, indent=4))
    else:
        debug(f'{bgc.FAIL}Failed to execute workflow:{bgc.ENDC}')
    return r.text, r.status_code


#
## Unit Test - helps testing the function locally
## Uncomment r=handle('...') to test the function with the event samples provided below test without deploying to OpenFaaS
#
if __name__ == '__main__':
    VRO_CONFIG = 'vroconfig.toml'
    DEBUG = True
    os.environ['insecure_ssl'] = 'true'
    os.environ['vro_workflow_id'] = '5fff3097-61d4-4a5b-929c-9a1ce07ec195'
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
    #r=handle('{"id":"17e1027a-c865-4354-9c21-e8da3df4bff9","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"UserLogoutSessionEvent","time":"2020-04-14T00:28:36.455112549Z","data":{"Key":7775,"ChainId":7775,"CreatedTime":"2020-04-14T00:28:35.221698Z","UserName":"machine-b8eb9a7f","Datacenter":null,"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"User machine-b8ebe7eb9a7f@127.0.0.1 logged out (login time: Tuesday, 14 April, 2020 12:28:35 AM, number of API invocations: 34, user agent: pyvmomi Python/3.7.5 (Linux; 4.19.84-1.ph3; x86_64))","ChangeTag":"","IpAddress":"127.0.0.1","UserAgent":"pyvmomi Python/3.7.5 (Linux; 4.19.84-1.ph3; x86_64)","CallCount":34,"SessionId":"52edf160927","LoginTime":"2020-04-14T00:28:35.071817Z"},"datacontenttype":"application/json"}')
    # Eventex : vim.event.ResourceExhaustionStatusChangedEvent
    #r=handle('{"id":"0707d7e0-269f-42e7-ae1c-18458ecabf3d","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/eventex","subject":"vim.event.ResourceExhaustionStatusChangedEvent","time":"2020-04-14T00:20:15.100325334Z","data":{"Key":7715,"ChainId":7715,"CreatedTime":"2020-04-14T00:20:13.76967Z","UserName":"machine-bb9a7f","Datacenter":null,"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"vCenter Log File System Resource status changed from Yellow to Green on vcsa01.lab.local  ","ChangeTag":"","EventTypeId":"vim.event.ResourceExhaustionStatusChangedEvent","Severity":"info","Message":"","Arguments":[{"Key":"resourceName","Value":"storage_util_filesystem_log"},{"Key":"oldStatus","Value":"yellow"},{"Key":"newStatus","Value":"green"},{"Key":"reason","Value":" "},{"Key":"nodeType","Value":"vcenter"},{"Key":"_sourcehost_","Value":"vcsa01.lab.local"}],"ObjectId":"","ObjectType":"","ObjectName":"","Fault":null},"datacontenttype":"application/json"}')
    # Standard : DrsVmPoweredOnEvent
    #r=handle('{"id":"36715df0-28e8-4e75-bc38-5af1ce41f3fb","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DrsVmPoweredOnEvent","time":"2020-08-24T13:28:34.782099207Z","data":{"Key":23763981,"ChainId":23763979,"CreatedTime":"2020-08-24T13:28:34.480388Z","UserName":"Administrator","Datacenter":{"Name":"Staging","Datacenter":{"Type":"Datacenter","Value":"datacenter-21"}},"ComputeResource":{"Name":"Staging","ComputeResource":{"Type":"ClusterComputeResource","Value":"domain-c26"}},"Host":{"Name":"esxi01.pdotk.local","Host":{"Type":"HostSystem","Value":"host-409"}},"Vm":{"Name":"Win 10 Client","Vm":{"Type":"VirtualMachine","Value":"vm-809"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"DRS powered On Win 10 Client on esxi01.pdotk.local in  Staging","ChangeTag":"","Template":false},"datacontenttype":"application/json"}')
    # Standard : VmPoweredOffEvent
    #r=handle('{"id":"d77a3767-1727-49a3-ac33-ddbdef294150","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"VmPoweredOffEvent","time":"2020-04-14T00:33:30.838669841Z","data":{"Key":7825,"ChainId":7821,"CreatedTime":"2020-04-14T00:33:30.252792Z","UserName":"Administrator","Datacenter":{"Name":"PKLAB","Datacenter":{"Type":"Datacenter","Value":"datacenter-3"}},"ComputeResource":{"Name":"esxi01.pdotk.local","ComputeResource":{"Type":"ComputeResource","Value":"domain-s29"}},"Host":{"Name":"esxi01.pdotk.local","Host":{"Type":"HostSystem","Value":"host-31"}},"Vm":{"Name":"Test VM","Vm":{"Type":"VirtualMachine","Value":"vm-33"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"Test VM on  esxi01.pdotk.local in PKLAB is powered off","ChangeTag":"","Template":false},"datacontenttype":"application/json"}')
    # Standard : DvsPortLinkUpEvent
    #r=handle('{"id":"a10f8571-fc2a-40db-8df6-8284cecf5720","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DvsPortLinkUpEvent","time":"2020-07-02T15:16:13.43892986Z","data":{"Key":130277,"ChainId":130277,"CreatedTime":"2020-07-02T15:16:11.207727Z","UserName":"","Datacenter":{"Name":"Lab","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":{"Name":"Lab Switch","Dvs":{"Type":"VmwareDistributedVirtualSwitch","Value":"dvs-22"}},"FullFormattedMessage":"The dvPort 2 link was up in the vSphere Distributed Switch Lab Switch in Lab","ChangeTag":"","PortKey":"2","RuntimeInfo":null},"datacontenttype":"application/json"}')
    # Standard : DatastoreRenamedEvent
    #r=handle('{"id":"369b403a-6729-4b0b-893e-01383c8307ba","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DatastoreRenamedEvent","time":"2020-07-02T21:44:11.09338265Z","data":{"Key":130669,"ChainId":130669,"CreatedTime":"2020-07-02T21:44:08.578289Z","UserName":"","Datacenter":{"Name":"Lab","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"Renamed datastore from esxi04-local to esxi04-localZ in Lab","ChangeTag":"","Datastore":{"Name":"esxi04-localZ","Datastore":{"Type":"Datastore","Value":"datastore-3313"}},"OldName":"esxi04-local","NewName":"esxi04-localZ"},"datacontenttype":"application/json"}')
    # Standard : DVPortgroupRenamedEvent
    #r=handle('{"id":"aab77fd1-41ed-4b51-89d3-ef3924b09de1","source":"https://vcsa01.lab.local/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"DVPortgroupRenamedEvent","time":"2020-07-03T19:36:38.474640186Z","data":{"Key":132376,"ChainId":132375,"CreatedTime":"2020-07-03T19:36:32.525906Z","UserName":"Administrator","Datacenter":{"Name":"Lab","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":null,"Host":null,"Vm":null,"Ds":null,"Net":{"Name":"vMotion AZ","Network":{"Type":"DistributedVirtualPortgroup","Value":"dvportgroup-3357"}},"Dvs":{"Name":"10G Switch A","Dvs":{"Type":"VmwareDistributedVirtualSwitch","Value":"dvs-3355"}},"FullFormattedMessage":"dvPort group vMotion A in Lab was renamed to vMotion AZ","ChangeTag":"","OldName":"vMotion A","NewName":"vMotion AZ"},"datacontenttype":"application/json"}')
    # Standard : VmReconfiguredEvent
    r=handle('{"id":"0a9366da-d752-4a8c-a23c-927afaa92709","source":"https://vcsa01.lab.core.pilue.co.uk/sdk","specversion":"1.0","type":"com.vmware.event.router/event","subject":"VmReconfiguredEvent","time":"2020-08-25T19:25:51.483148436Z","data":{"Key":361293,"ChainId":361292,"CreatedTime":"2020-08-25T19:25:49.597893Z","UserName":"david","Datacenter":{"Name":"Pilue","Datacenter":{"Type":"Datacenter","Value":"datacenter-2"}},"ComputeResource":{"Name":"Lab","ComputeResource":{"Type":"ClusterComputeResource","Value":"domain-c47"}},"Host":{"Name":"esxi01.lab.core.pilue.co.uk","Host":{"Type":"HostSystem","Value":"host-3605"}},"Vm":{"Name":"1850","Vm":{"Type":"VirtualMachine","Value":"vm-3089"}},"Ds":null,"Net":null,"Dvs":null,"FullFormattedMessage":"Reconfigured 1850 on esxi01.lab.core.pilue.co.uk in Pilue.  \\n \\nModified:  \\n \\nconfig.hardware.numCPU: 2 -\\u003e 1; \\n\\nconfig.cpuAllocation.shares.shares: 2000 -\\u003e 1000; \\n\\n Added:  \\n \\n Deleted:  \\n \\n","ChangeTag":"","Template":false,"ConfigSpec":{"ChangeVersion":"2020-08-25T19:10:09.32504Z","Name":"","Version":"","CreateDate":"2020-01-24T19:13:15.611448Z","Uuid":"","InstanceUuid":"","NpivNodeWorldWideName":null,"NpivPortWorldWideName":null,"NpivWorldWideNameType":"","NpivDesiredNodeWwns":0,"NpivDesiredPortWwns":0,"NpivTemporaryDisabled":null,"NpivOnNonRdmDisks":null,"NpivWorldWideNameOp":"","LocationId":"","GuestId":"","AlternateGuestName":"","Annotation":"","Files":null,"Tools":null,"Flags":null,"ConsolePreferences":null,"PowerOpInfo":null,"NumCPUs":1,"NumCoresPerSocket":0,"MemoryMB":0,"MemoryHotAddEnabled":null,"CpuHotAddEnabled":null,"CpuHotRemoveEnabled":null,"VirtualICH7MPresent":null,"VirtualSMCPresent":null,"DeviceChange":null,"CpuAllocation":null,"MemoryAllocation":null,"LatencySensitivity":null,"CpuAffinity":null,"MemoryAffinity":null,"NetworkShaper":null,"CpuFeatureMask":null,"ExtraConfig":null,"SwapPlacement":"","BootOptions":null,"VAppConfig":null,"FtInfo":null,"RepConfig":null,"VAppConfigRemoved":null,"VAssertsEnabled":null,"ChangeTrackingEnabled":null,"Firmware":"","MaxMksConnections":0,"GuestAutoLockEnabled":null,"ManagedBy":null,"MemoryReservationLockedToMax":null,"NestedHVEnabled":null,"VPMCEnabled":null,"ScheduledHardwareUpgradeInfo":null,"VmProfile":null,"MessageBusTunnelEnabled":null,"Crypto":null,"MigrateEncryption":""},"ConfigChanges":{"Modified":"config.hardware.numCPU: 2 -\\u003e 1; \\n\\nconfig.cpuAllocation.shares.shares: 2000 -\\u003e 1000; \\n\\n","Added":"","Deleted":""}},"datacontenttype":"application/json"}')
    print(f'Response status code: {r[1]} - {r[0]}')
    #print(r[0])