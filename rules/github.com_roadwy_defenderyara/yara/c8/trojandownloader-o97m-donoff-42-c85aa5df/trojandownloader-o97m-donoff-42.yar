rule TrojanDownloader_O97M_Donoff_42{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 22 20 26 20 22 6a 22 20 26 20 22 73 22 } 		$a_01_1 = {57 73 2d 2d 28 2d 63 72 2d 2d 28 2d 69 70 2d 2d 28 2d 74 2e } 		$a_01_2 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 20 22 20 26 20 43 53 74 72 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}