rule TrojanDownloader_Linux_Bartallex_4{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 6c 75 65 66 69 6c 65 2e 62 69 7a 2f 64 6f 77 6e 6c 6f 61 64 73 2f 65 38 32 30 31 30 35 64 62 39 36 30 65 36 35 62 37 63 64 37 65 38 65 36 35 65 33 65 32 66 32 35 31 37 39 38 31 34 34 2e 65 78 65 } 		$a_01_1 = {79 28 22 61 74 61 44 70 70 41 22 } 		$a_01_2 = {22 50 4d 45 54 22 } 		$a_01_3 = {22 2e 65 78 65 22 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}