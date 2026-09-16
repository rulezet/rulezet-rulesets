rule TrojanDownloader_O97M_Bartallex_6{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 48 54 20 3d 20 22 22 20 26 20 22 68 74 22 20 26 20 22 74 22 20 26 20 22 70 3a 2f 2f 22 20 26 20 22 22 } 		$a_01_1 = {53 50 49 43 20 3d 20 22 22 20 26 20 22 73 22 20 26 20 22 61 76 22 20 26 20 22 65 70 69 22 20 2b 20 22 63 2e 73 75 22 20 2b 20 22 2f 22 } 		$a_01_2 = {4c 4e 53 53 20 3d 20 22 6c 6e 73 2e 74 78 74 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}