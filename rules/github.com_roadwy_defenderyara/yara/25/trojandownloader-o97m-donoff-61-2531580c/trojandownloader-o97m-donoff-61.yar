rule TrojanDownloader_O97M_Donoff_61{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {37 67 79 6a 67 67 35 72 36 22 2c 20 22 } 		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 22 61 75 74 6f 62 6c 75 65 6c 69 74 65 2e } 		$a_02_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-08] 28 } 		$a_02_3 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 [0-08] 28 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}