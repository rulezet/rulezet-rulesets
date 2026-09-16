rule TrojanDownloader_Linux_Bartallex_I{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.I,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 63 6f 79 6c 2e 63 22 20 26 20 22 6f 6d 2f 77 22 20 26 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 74 75 62 65 70 72 65 73 73 2d 63 6f 6e 74 65 6e 74 2f 22 } 		$a_01_1 = {74 61 6d 65 6c 61 67 69 6c 62 65 72 74 6d 64 2e 63 22 20 26 20 22 6f 6d 2f 22 } 		$a_01_2 = {22 36 36 38 33 36 34 38 37 31 36 32 22 } 		$a_01_3 = {22 2e 74 22 20 26 20 22 78 74 22 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}