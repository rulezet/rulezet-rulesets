rule TrojanDownloader_O97M_Obfuse_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f 35 6d 73 36 6b 34 75 6e 6f 37 71 78 36 69 74 63 2f 66 6f 72 74 6e 69 74 65 2e 65 78 65 22 2c 20 46 61 6c 73 65 } 		$a_01_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 28 22 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 66 6f 72 74 6e 69 74 65 2e 65 78 65 22 29 2c 20 32 } 		$a_01_2 = {53 68 65 6c 6c 20 28 22 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 46 6f 72 74 6e 69 74 65 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}