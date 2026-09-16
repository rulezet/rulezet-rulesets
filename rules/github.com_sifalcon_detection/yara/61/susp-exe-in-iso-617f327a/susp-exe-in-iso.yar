rule SUSP_EXE_in_ISO: EXE ISO {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects ISO files that contains an Exe file. Does not need to be malicious"
		date = "19.02.2022"
		reference = "Internal Research"

	strings:
		$magic = { 43 44 30 30 31 }
		$mz = { 4D 5A }

	condition:
		filesize > 100KB 
		and filesize < 800KB 
		and $magic 
		and $mz
}