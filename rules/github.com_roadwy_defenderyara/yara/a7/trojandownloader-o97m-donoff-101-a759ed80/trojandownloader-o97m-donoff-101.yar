rule TrojanDownloader_O97M_Donoff_101{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 2f 2f 73 61 63 72 69 66 69 63 65 72 79 2e 74 6f 70 2f 6c 6c 2f 6c 64 64 2e 70 68 70 27 2c } 		$a_01_1 = {22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 57 69 6e 33 32 3b 20 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 29 27 29 3b 22 } 		$a_01_2 = {25 54 45 4d 50 25 2e 65 5e 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}