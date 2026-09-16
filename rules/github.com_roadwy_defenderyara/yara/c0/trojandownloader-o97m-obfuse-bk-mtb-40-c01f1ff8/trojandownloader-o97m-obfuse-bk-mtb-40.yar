rule TrojanDownloader_O97M_Obfuse_BK_MTB_40{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 67 6f 67 6f 2e 43 72 65 61 74 65 28 22 6d 73 68 74 61 20 68 74 74 70 3a 5c 5c 6a 2e 6d 70 2f 34 73 64 6e 34 73 6b 6e 6b 34 6e 73 6b 66 22 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 67 6f 67 6f 49 44 29 } 		$a_01_1 = {3d 20 6c 6f 76 65 32 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 62 65 6d 53 63 72 69 70 74 69 6e 67 2e 53 57 62 65 6d 4c 6f 63 61 74 6f 72 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}