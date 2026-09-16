rule TrojanDownloader_Linux_Bartallex_B_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 73 69 67 75 61 6e 61 73 2e 63 6f 6d 2e 6d 78 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 63 68 72 6f 6d 65 } 		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 22 29 } 		$a_01_2 = {22 2e 76 22 20 2b 20 22 62 22 20 2b 20 22 73 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}