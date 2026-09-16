rule TrojanDownloader_O97M_Obfuse_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 69 6c 65 28 27 68 74 74 70 3a 2f 2f 6f 6e 65 64 72 69 76 65 6e 65 74 2e 78 79 7a 2f 77 6f 72 6b 2f 33 30 2e 76 62 73 27 2c 22 } 		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 56 78 58 74 67 52 67 57 59 28 22 5f 5b 6b 7a 71 78 7c 36 5b 70 6d 74 74 22 2c 20 22 38 22 29 29 } 		$a_03_2 = {2e 52 75 6e 20 [0-25] 2c 20 76 62 48 69 64 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}