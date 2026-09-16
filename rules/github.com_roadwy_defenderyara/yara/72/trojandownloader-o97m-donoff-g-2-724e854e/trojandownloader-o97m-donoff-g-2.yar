rule TrojanDownloader_O97M_Donoff_G_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {29 20 2d 20 31 20 54 6f 20 30 20 53 74 65 70 20 2d 32 } 		$a_01_1 = {2e 54 79 70 65 20 3d 20 30 20 2b 20 31 } 		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 4d 6f 64 75 6c 65 33 2e } 		$a_01_3 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}