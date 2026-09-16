rule TrojanDownloader_O97M_Donoff_55{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-20] 45 6e 64 20 53 75 62 } 		$a_01_1 = {3d 20 46 6f 72 6d 31 2e 45 64 69 74 32 2e 54 65 78 74 } 		$a_03_2 = {20 54 68 65 6e [0-04] 53 68 65 6c 6c 20 } 		$a_01_3 = {3d 20 22 43 41 31 35 72 39 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}