rule TrojanDownloader_O97M_Donoff_26{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 27 25 61 50 70 44 41 54 22 } 		$a_01_1 = {22 74 65 64 2e 65 78 65 27 22 } 		$a_01_2 = {22 43 4d 44 2e 65 58 45 20 22 } 		$a_01_3 = {22 65 62 5e 63 4c 69 45 6e 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}