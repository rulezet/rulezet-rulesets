rule TrojanDownloader_O97M_Donoff_G_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-20] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 25 74 65 6d 70 25 22 29 } 		$a_01_1 = {20 26 20 22 5c 61 6d 6e 65 73 74 69 63 2e 65 78 65 22 } 		$a_01_2 = {50 75 74 20 23 68 61 6e 61 70 65 72 2c 20 2c 20 43 42 79 74 65 28 22 26 22 20 2b 20 43 68 72 28 31 32 35 20 2d 20 35 33 29 20 26 20 66 72 61 75 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}