Add-Type -AssemblyName System.Web

# Process function Secrets passed in
$SECRETS_FILE = "/var/openfaas/secrets/vro-secrets"
$SECRETS_CONFIG = (Get-Content -Raw -Path $SECRETS_FILE | ConvertFrom-Json)

# Process payload sent from vCenter Server Event
$json = $args | ConvertFrom-Json
if($env:function_debug -eq "true") {
    Write-Host "DEBUG: json=`"$($json | Format-List | Out-String)`""
}

$stringData = [System.Net.WebUtility]::HtmlEncode($args)
# Requires a vRO workflow that takes a single string input parameter called "eventData"
$body = @"
{
    "parameters":
	[
        {
            "value": {
                "string":{
                    "value": "$($stringData)"
                }
            },
            "type": "string",
            "name": "eventData",
            "scope": "local"
	}
	]
}
"@

# Basic Auth for vRO execution
$pair = "$($SECRETS_CONFIG.VRO_USERNAME):$($SECRETS_CONFIG.VRO_PASSWORD)"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"

$headers = @{
    "Authorization"="$basicAuthValue";
    "Accept="="application/json";
    "Content-Type"="application/json";
}

$vroUrl = "https://$($SECRETS_CONFIG.VRO_SERVER):443/vco/api/workflows/$($SECRETS_CONFIG.VRO_WORKFLOW_ID)/executions"

if($env:function_debug -eq "true") {
    Write-Host "DEBUG: json=$args"
    Write-Host "DEBUG: vRoURL=`"$($vroUrl | Format-List | Out-String)`""
    Write-Host "DEBUG: headers=`"$($headers | Format-List | Out-String)`""
    Write-Host "DEBUG: body=$body"
}

Write-Host "Sending event data to vRO..."
if($env:skip_vro_cert_check -eq "true") {
    Invoke-Webrequest -Uri $vroUrl -Method POST -Headers $headers -SkipHeaderValidation -Body $body -SkipCertificateCheck
} else {
    Invoke-Webrequest -Uri $vroUrl -Method POST -Headers $headers -SkipHeaderValidation -Body $body
}
