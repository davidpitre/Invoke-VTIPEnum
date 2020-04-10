<#
	.SYNOPSIS
		Virus Total IP Enum
	
	.DESCRIPTION
		Use Virus Total to analyse a supplied list of IP Addresses in a CSV Format
		to determine if they have been associated with malious activity.
		Unless you have a paid for Virus Total API you are limited to a query
		once every 20 seconds up to 1000 per day, which may result in the script 
		taking a long time to complete depending on the size of the source list.
	
	.PARAMETER Path
		Input CSV containing a list of IP Addresses with the column name = IPAddress
	
	.PARAMETER OutputPath
		Path to the output CSV report
	
	.PARAMETER VirusTotalAPIKey
		Virus total API Key - Free from https://www.virustotal.com/gui/join-us
		The free api has a rate limit of 4 requests a minute and 1000 per day.
	
	.EXAMPLE
		PS C:\> .\Invoke-VTIPEnum.ps1 -Path C:\Source\IPList.csv -OutputPath C:\Source\EnrichedIPs.csv -VirusTotalAPIKey "<key>"
	
	.NOTES
		===========================================================================
		 Created on:   		03/04/2020
		 Created by:   		David Pitre
		 Filename:     		invoke-VTIPEnum.ps1
		 Version:			0.1
		 Classification:		Public

		 TODO
		 1. Implement logic to better handle Virus Totals API
		===========================================================================
	
	.LINK
		https://github.com/davidpitre/Invoke-VTIPEnum
#>
param
(
	[Parameter(Mandatory = $true)]
	[string]$Path,
	[Parameter(Mandatory = $true)]
	[string]$OutputPath,
	[Parameter(Mandatory = $true)]
	[string]$VirusTotalAPIKey
)

#region Variables
#Source IP Address list CSV - The column needs to be IPAddress"
[array]$CSVIPAddresses = Import-Csv -Path $Path
#The Output URL for the Report
[array]$CSVIPAddressesReportPath = $OutputPath
#API Key for Virus Total - Use mine for now but its free to get your own
[string]$VTApiKey = $VirusTotalAPIKey
#Array object for our collected data
[array]$Global:EnrichedIPAddressData = $null
#endregion

#region Main code block
function Get-VTIPEnum
{
	param
	(
		[string]$IP
	)
	
	BEGIN
	{
		[string]$VTApiURL = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={0}&ip={1}" -f $VTApiKey, $IP
	}
	PROCESS
	{
		Write-Host "Enriching Destination: "$IP
		try
		{
			$VTIPReport = Invoke-RestMethod -Method 'GET' -Uri $VTApiURL
		}
		catch
		{
			throw "Unable to query Virus Total's API"
		}
		
		$VTIPReport
		$VTPIPObject = New-Object -TypeName PSCustomObject
		$VTPIPObject | Add-Member -membertype NoteProperty -Name "IP_Address" -Value ([string]$IP)
		$VTPIPObject | Add-Member -membertype NoteProperty -Name "Country" -Value ([string]$VTIPReport.country)
		$VTPIPObject | Add-Member -membertype NoteProperty -Name "AS_Owner" -Value ([string]$VTIPReport.as_owner)
		$VTPIPObject | Add-Member -membertype NoteProperty -Name "Detected_URLs" -Value ([string]$VTIPReport.detected_urls -join ',')
		$VTPIPObject | Add-Member -membertype NoteProperty -Name "Observed_hostnames" -Value ([string]$VTIPReport.resolutions.hostname -join ',')
		[array]$Global:EnrichedIPAddressData += $VTPIPObject
	}
	END
	{
		Start-Sleep -Seconds 21
	}
}

foreach ($IP in $CSVIPAddresses.IPAddress)
{
	Get-VTIPEnum -IP $IP | Export-Csv -Path $CSVIPAddressesReportPath -NoClobber -NoTypeInformation -Append
}
#endregion
