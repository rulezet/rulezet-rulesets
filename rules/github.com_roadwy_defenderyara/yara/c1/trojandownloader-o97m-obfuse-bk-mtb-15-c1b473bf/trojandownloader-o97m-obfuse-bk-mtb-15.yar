rule TrojanDownloader_O97M_Obfuse_BK_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 73 5f 5f 5f 5f 5f 47 20 3d 20 43 68 72 57 28 6d 5f 5f 5f 5f 5f 6e 20 2d 20 36 39 29 } 		$a_01_1 = {2e 52 75 6e 28 6c 63 77 66 69 64 78 6b 62 6c 66 6b 62 6f 6b 76 6a 77 6c 71 71 72 64 68 76 6b 77 65 66 6e 71 6c 67 79 68 2c 20 6e 6f 66 70 70 78 75 75 6a 78 7a 63 73 6c 6a 6b 62 6b 62 74 61 75 6b 6a 62 78 78 6b 6a 6d 77 65 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}