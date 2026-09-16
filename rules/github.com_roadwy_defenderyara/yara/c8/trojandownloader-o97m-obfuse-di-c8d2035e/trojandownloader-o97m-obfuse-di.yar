rule TrojanDownloader_O97M_Obfuse_DI{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DI,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } 		$a_03_1 = {47 65 74 4f 62 6a 65 63 74 28 28 [0-10] 20 2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b 20 [0-10] 20 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 29 2e 43 72 65 61 74 65 } 		$a_01_2 = {3d 20 22 72 73 68 65 4c 6c 22 20 2b 20 22 20 2d 65 22 20 2b } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}