rule TrojanDownloader_Linux_Bartallex_5{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 57 56 46 38 43 7a 36 48 28 29 } 		$a_01_1 = {54 6f 6d 6a 78 4a 39 47 44 58 31 68 72 7a 2e 4f 70 65 6e 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 37 } 		$a_01_2 = {57 4c 34 4a 6f 38 45 78 77 36 37 76 41 44 2e 48 77 4f 43 78 35 31 63 41 7a 34 71 2c 20 32 } 		$a_01_3 = {2e 78 6a 53 54 64 76 50 76 6f 4d 63 57 4d 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}