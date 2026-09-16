rule TrojanDownloader_O97M_Bartallex_9{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 73 70 72 65 73 65 6e 74 61 74 69 6f 6e 70 72 6f 64 75 63 74 73 2e 63 6f 6d 2f } 		$a_01_1 = {22 63 68 61 6d 65 6c 65 6f 6e 70 61 69 6e 74 77 6f 72 6b 73 2e 63 6f 6d 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 22 20 2b 20 22 74 65 6e 74 2f 70 6c 22 20 2b 20 22 75 67 69 6e 73 2f 77 22 20 2b 20 22 70 2d 6a 71 75 22 20 2b 20 22 65 72 79 2d 6c 69 67 22 20 2b 20 22 68 74 62 6f 78 2f 73 74 79 22 20 2b 20 22 6c 65 73 2f 69 6d 61 67 22 20 2b 20 22 65 73 2f 68 65 5f 49 4c 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}