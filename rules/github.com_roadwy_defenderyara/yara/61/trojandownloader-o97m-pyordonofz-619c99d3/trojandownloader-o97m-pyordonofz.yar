rule TrojanDownloader_O97M_Pyordonofz{
	meta:
		description = "TrojanDownloader:O97M/Pyordonofz,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 71 73 6e 2e 76 66 71 2e 54 65 78 74 20 26 20 67 6c 7a 65 68 73 6b 69 71 6f 63 76 67 71 64 66 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}