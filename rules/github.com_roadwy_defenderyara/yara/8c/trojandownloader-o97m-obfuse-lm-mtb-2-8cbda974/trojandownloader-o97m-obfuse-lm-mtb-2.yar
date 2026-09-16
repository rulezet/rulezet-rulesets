rule TrojanDownloader_O97M_Obfuse_LM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-14] 28 22 77 61 5f 3a 77 61 5f 3a 77 69 77 61 5f 3a 6e 6d 67 77 61 5f 3a 6d 74 73 3a 77 61 5f 3a 57 77 61 5f 3a 77 61 5f 3a 77 61 5f 3a 69 77 61 5f 3a 6e 33 77 61 5f 3a 32 5f 50 77 61 5f 3a 72 6f 77 61 5f 3a 63 65 77 61 5f 3a 73 73 77 61 5f 3a 22 29 29 2e 43 72 65 61 74 65 28 [0-14] 2c } 		$a_03_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-14] 29 20 2b } 		$a_01_2 = {2e 53 68 6f 77 57 69 6e 64 6f 77 21 20 3d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}