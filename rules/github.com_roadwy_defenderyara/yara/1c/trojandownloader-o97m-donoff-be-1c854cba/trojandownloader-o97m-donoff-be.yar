rule TrojanDownloader_O97M_Donoff_BE{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BE,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 70 6c 69 74 28 22 37 32 38 5f 38 31 32 5f 38 31 32 5f 37 38 34 5f 34 30 36 5f 33 32 39 5f 33 32 39 5f } 		$a_01_1 = {2c 20 22 3a 3a 22 29 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } 		$a_01_3 = {22 5f 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}