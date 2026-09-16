rule TrojanDownloader_O97M_Obfuse_BK_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 6e 6f 20 3d 20 61 6e 6f 20 26 20 } 		$a_01_1 = {2e 52 75 6e 28 77 76 77 6c 6e 6d 6c 73 64 79 76 61 66 65 66 76 75 64 6e 6a 62 6e 73 65 61 64 74 6d 2c 20 66 6e 6c 62 6c 67 6f 67 7a 6a 78 75 68 7a 62 69 76 6f 72 66 78 77 64 75 76 6e 65 6b 77 77 67 6f 72 6a 74 66 78 78 71 29 } 		$a_01_2 = {3d 20 43 68 72 28 62 67 66 62 67 20 2d 20 31 31 34 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}