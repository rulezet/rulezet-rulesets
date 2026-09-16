rule TrojanDownloader_O97M_Obfuse_BK_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29 } 		$a_01_1 = {44 43 55 47 7a 55 2e 4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f 6d 6f 6f 6e 73 68 69 6e 65 2d 6d 68 74 2e 62 65 73 74 2f 63 68 72 6f 6d 65 2e 6a 70 67 22 } 		$a_01_2 = {2e 74 72 61 6e 73 66 6f 72 6d 4e 6f 64 65 20 28 44 43 55 47 7a 55 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}