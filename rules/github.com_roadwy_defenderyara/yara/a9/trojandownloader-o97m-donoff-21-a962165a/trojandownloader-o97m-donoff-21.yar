rule TrojanDownloader_O97M_Donoff_21{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 22 65 2e 74 73 6f 68 6e 76 73 5c 70 6d 65 54 5c 6c 61 63 6f 4c 5c 25 41 54 41 44 50 50 41 25 22 29 20 26 20 22 78 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}