rule OBFUS_VBS_Reverse_StartUp {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detecs reversed StartUp Path. Sometimes used as obfuscation"

	strings:
		$reverse = "\\putratS\\smargorP\\uneM" wide nocase 
	condition:
		filesize < 200KB and $reverse
}