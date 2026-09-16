rule TrojanDownloader_O97M_Bartallex_10{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 77 77 77 2e 69 6e 22 20 2b 20 22 63 61 6c 74 61 6d 69 6e 74 65 2e 69 6e 22 20 2b 20 22 66 6f 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 22 20 2b 20 22 6f 61 64 73 2f 32 30 31 22 20 2b 20 22 35 2f 30 22 20 2b 20 22 36 2f 22 } 		$a_01_1 = {22 77 77 77 2e 69 73 63 6d 6f 22 20 2b 20 22 6e 74 65 67 72 61 6e 61 72 6f 2e 69 74 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 22 20 2b 20 22 6f 61 64 73 2f 32 30 31 22 20 2b 20 22 35 2f 30 22 20 2b 20 22 36 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}