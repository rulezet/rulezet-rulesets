rule TrojanDownloader_Linux_Bartallex_A_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {42 41 52 54 20 3d 20 22 22 20 2b 20 42 41 52 54 32 } 		$a_00_1 = {4b 69 6c 6c 20 58 50 46 49 4c 45 44 49 52 } 		$a_00_2 = {22 63 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 22 } 		$a_02_3 = {53 75 62 20 41 75 74 6f [0-02] 4f 70 65 6e 28 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}