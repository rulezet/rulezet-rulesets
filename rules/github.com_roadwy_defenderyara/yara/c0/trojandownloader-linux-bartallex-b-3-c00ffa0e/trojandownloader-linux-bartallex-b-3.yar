rule TrojanDownloader_Linux_Bartallex_B_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 72 69 74 73 63 68 66 69 73 63 68 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 31 2f 30 38 2f 6c 69 63 65 6e 73 65 } 		$a_01_1 = {43 68 72 28 33 34 29 20 2b 20 22 34 2e 65 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 2b 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 78 65 22 20 2b 20 43 68 72 28 33 34 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}