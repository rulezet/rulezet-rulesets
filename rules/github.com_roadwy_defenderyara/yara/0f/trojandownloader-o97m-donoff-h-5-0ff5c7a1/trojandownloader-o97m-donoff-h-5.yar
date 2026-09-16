rule TrojanDownloader_O97M_Donoff_H_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } 		$a_01_1 = {2b 20 31 3a 20 44 6f 45 76 65 6e 74 73 } 		$a_03_2 = {2e 54 65 78 74 42 6f 78 31 20 2b 20 90 05 0c 06 61 2d 7a 41 2d 5a 2e 54 65 78 74 42 6f 78 32 20 2b 20 90 1b 00 2e 54 65 78 74 42 6f 78 33 20 2b } 		$a_01_3 = {2c 20 76 62 48 69 64 65 } 		$a_01_4 = {41 6c 65 6c 50 64 63 73 79 71 4f 65 51 47 70 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3) >=10
 
}