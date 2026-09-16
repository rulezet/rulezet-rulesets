rule SUSP_PowerShell_Download_Temp_Rundll : powershell download {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		date = "09.02.2022"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		filesize < 100KB 
		and $location 
		and $download 
		and $rundll
}