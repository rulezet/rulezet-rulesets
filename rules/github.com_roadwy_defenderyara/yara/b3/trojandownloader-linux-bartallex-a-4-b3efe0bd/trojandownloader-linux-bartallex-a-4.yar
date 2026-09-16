rule TrojanDownloader_Linux_Bartallex_A_4{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 39 31 2e 32 32 30 2e 31 33 31 } 		$a_03_1 = {2f 75 70 64 [0-01] 2f 69 6e 73 74 61 6c 6c } 		$a_00_2 = {22 63 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 22 20 2b 20 42 41 52 54 } 		$a_01_3 = {4b 69 6c 6c 20 58 50 46 49 4c 45 44 49 52 } 		$a_00_4 = {42 41 52 54 20 3d 20 22 22 20 2b 20 42 41 52 54 32 20 2b 20 43 68 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}