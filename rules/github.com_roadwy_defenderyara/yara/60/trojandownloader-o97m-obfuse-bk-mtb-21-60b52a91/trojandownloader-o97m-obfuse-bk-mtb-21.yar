rule TrojanDownloader_O97M_Obfuse_BK_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4e 6e 55 78 73 2e 72 4c 48 4c 56 28 79 46 78 67 2c 20 79 46 78 67 32 29 } 		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 66 6a 6b 64 73 66 28 29 20 2b 20 6b 6c 73 64 6b 28 29 20 2b 20 77 6c 66 66 66 28 29 29 } 		$a_01_2 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 6e 31 2c 20 41 32 2c 20 22 22 2c 20 22 22 2c 20 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}