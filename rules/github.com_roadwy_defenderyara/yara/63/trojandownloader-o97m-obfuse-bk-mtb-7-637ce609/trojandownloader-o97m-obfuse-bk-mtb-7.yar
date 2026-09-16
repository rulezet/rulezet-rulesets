rule TrojanDownloader_O97M_Obfuse_BK_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 70 6b 6d 20 3d 20 74 70 6b 6d 20 26 } 		$a_01_1 = {2e 52 75 6e 28 69 64 69 6d 71 73 7a 73 69 66 79 6e 74 2c 20 72 74 63 63 69 62 6e 75 67 78 71 76 74 63 77 74 69 6c 72 62 67 71 68 63 77 6b 65 29 } 		$a_01_2 = {64 5f 5f 61 73 20 3d 20 43 68 72 57 28 6c 5f 5f 6b 20 2d 20 36 32 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}