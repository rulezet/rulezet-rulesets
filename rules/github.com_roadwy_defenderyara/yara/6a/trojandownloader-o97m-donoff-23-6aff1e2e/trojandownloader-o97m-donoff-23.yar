rule TrojanDownloader_O97M_Donoff_23{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 43 4d 64 2e 22 } 		$a_01_1 = {3d 20 22 74 70 3a 2f 22 } 		$a_03_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}