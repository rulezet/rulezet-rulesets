rule SUSP_PowerShell_Base64_Decode : powershell b64 {
	meta:
		author = "SECUINFRA Falcon Team"
		description	= "Detects PowerShell code to decode Base64 data. This can yield many FP"
		date = "27.02.2022"

	strings:
		$b64_decode = "[System.Convert]::FromBase64String("

	condition:
		filesize < 500KB 
		and $b64_decode
}