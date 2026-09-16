rule TrojanDownloader_O97M_Donoff_82{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 54 4d 50 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 52 75 6e 41 66 74 65 72 44 6f 77 6e 6c 6f 61 64 } 		$a_01_1 = {49 66 20 52 75 6e 48 69 64 65 20 3d 20 54 72 75 65 20 54 68 65 6e } 		$a_01_2 = {53 68 65 6c 6c 20 46 75 6c 6c 53 61 76 65 50 61 74 68 2c 20 76 62 48 69 64 65 } 		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}