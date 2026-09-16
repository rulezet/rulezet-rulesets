rule TrojanDownloader_O97M_Donoff_38{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {22 63 4d 44 22 } 		$a_00_1 = {22 25 2e 45 22 } 		$a_01_2 = {22 74 74 70 22 } 		$a_01_3 = {22 3a 2f 2f 22 } 		$a_03_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}