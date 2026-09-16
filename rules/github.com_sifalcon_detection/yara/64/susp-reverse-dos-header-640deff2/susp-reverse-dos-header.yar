rule SUSP_Reverse_DOS_header : pe obfuscation {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "19.02.2022"
		description = "Detects an reversed DOS header"

	strings:
		$reversed = "edom SOD ni nur eb tonnac margorp sihT" ascii wide 

	condition:
		filesize < 500KB and $reversed
}