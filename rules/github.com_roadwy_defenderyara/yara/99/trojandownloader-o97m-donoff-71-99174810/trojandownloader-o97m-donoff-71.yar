rule TrojanDownloader_O97M_Donoff_71{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 69 74 63 6c 6f 75 64 2e 67 71 2f 73 64 6b } 		$a_01_1 = {64 6f 77 4e 4c 6f 61 44 46 69 6c 45 2e 69 4e 56 6f 4b 45 } 		$a_01_2 = {7b 30 7d 7b 32 7d 7b 31 7d 7b 33 7d 7b 35 7d 7b 36 7d 7b 34 7d } 		$a_01_3 = {27 53 74 27 2c 27 6f 63 65 73 73 27 2c 27 61 72 74 27 2c 27 2d 50 72 27 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}