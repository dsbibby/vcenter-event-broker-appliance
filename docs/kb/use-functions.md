---
layout: docs
toc_id: use-functions
title: VMware Event Broker Appliance - Using Functions
description: VMware Event Broker Appliance - Using Functions
permalink: /kb/use-functions
cta:
 title: What's next?
 description: Extend your vCenter quickly with our pre-built functions
 actions:
    - text: See our complete list of prebuilt functions - [here](/examples)
    - text: Learn how to write your own function - [here](contribute-functions).
---

# Getting started with using functions

The steps below describe a generalized deployment step of a function on the VMware Event Broker Appliance configured with OpenFaaS as the Event Processor. For customers looking to get started quickly, please look at deploying from our growing list of [Prebuilt Functions](/examples). The functions are organized by the language that they are written in and have well-documented README.md files with detailed deployment steps.

## Function deployment steps

For this walk-through, the `host-maint-alarms` function from the example folder is used. 

### Prerequisites

Before proceeding to deploy a function, you must have VMware Event Broker Appliance deployed and be able to login to OpenFaaS. 

```bash
#Use your appliance URL and OpenFaaS password 
export OPENFAAS_URL='https://veba.primp-industries.com'
faas-cli login -p YourPassword
```
> **NOTE:** You may have to use the `--tls-no-verify` flag as the appliance utilizes self-signed certificates by default. You can update the certificates following this guide [here](advanced-certificates)

An alternative way to log in if you don't want your password showing up in command history is to put the password in a text file and use this command:
```bash
cat password.txt | faas-cli login --password-stdin
```

### Step 1 - Clone repo

```
git clone https://github.com/vmware-samples/vcenter-event-broker-appliance
cd vcenter-event-broker-appliance/examples/powercli/hostmaint-alarms
git checkout master
```

### Step 2 - Edit the configuration files

* Edit `stack.yml` to update `gateway:` with the specific appliance URL in your environment. Notice event(s) next to `topics:` - all available events can be reviewed in the [vCenter Event Mapping](https://github.com/lamw/vcenter-event-mapping){:target="_blank"} document.

```yaml
version: 1.0
provider:
  name: openfaas
  gateway: https://veba.primp-industries.com
functions:
  powercli-entermaint:
    lang: powercli
    handler: ./handler
    image: vmware/veba-powercli-esx-maintenance:latest
    environment:
      write_debug: true
      read_debug: true
      function_debug: false
    secrets:
      - vc-hostmaint-config
    annotations:
      topic: EnteredMaintenanceModeEvent,ExitMaintenanceModeEvent
```

* Most functions also have a secrets configuration file that you must edit to match your environment. For the `hostmaint-alarms` function, the file is named `vc-hostmaint-config.json`
```json
{
    "VC" : "https://veba.primp-industries.com",
    "VC_USERNAME" : "veba@vsphere.local",
    "VC_PASSWORD" : "FillMeIn"
}
```
Then create the secret in OpenFaaS with this command:
```bash
faas-cli secret create vc-hostmaint-config --from-file=vc-hostmaint-config.json 
```


### Step 3 - Deploy function to VMware Event Broker Appliance

```
faas-cli deploy -f stack.yml
```

### Step 4 - Test and Invoke your functions

* Your function is now deployed to OpenFaaS and available for VMware Event Router to invoke when it sees a matching event
* You can also test or invoke your functions using the http endpoint for the function that OpenFaaS makes available. Pass the expected CloudEvents to the function as the http request parameter
