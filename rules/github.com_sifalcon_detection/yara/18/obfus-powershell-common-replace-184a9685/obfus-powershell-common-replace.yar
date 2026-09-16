rule OBFUS_PowerShell_Common_Replace {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "12.02.2022"
		description = "Detects the common usage of replace for obfuscation"

	strings:
		$replace = "replace(" nocase

	condition:
		filesize < 100KB 
		and #replace > 10
}