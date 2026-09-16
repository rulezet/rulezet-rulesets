rule TrojanDownloader_O97M_Donoff_J_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.J,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 7a 69 6d 6f 67 6f 73 74 6f 2e 72 75 } 		$a_01_1 = {2f 6e 6b 65 72 6e 65 6c 2e 65 78 65 } 		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 28 32 35 35 2c 20 73 42 75 66 66 65 72 29 } 		$a_01_3 = {53 68 65 6c 6c 20 4c 6f 63 61 6c 46 69 6c 65 2c 20 76 62 48 69 64 65 } 		$a_01_4 = {72 65 74 20 3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 48 54 54 50 66 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}