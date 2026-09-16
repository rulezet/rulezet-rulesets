rule TrojanDownloader_O97M_Donoff_63{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 [0-10] 2c 20 46 61 6c 73 65 } 		$a_01_1 = {50 72 69 76 61 74 65 20 53 75 62 20 49 6e 6b 50 69 63 74 75 72 65 31 5f 50 61 69 6e 74 65 64 } 		$a_03_2 = {20 3d 20 49 6e 53 74 72 [0-03] 28 [0-10] 2c 20 4d 69 64 28 } 		$a_01_3 = {26 20 4d 69 64 28 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}