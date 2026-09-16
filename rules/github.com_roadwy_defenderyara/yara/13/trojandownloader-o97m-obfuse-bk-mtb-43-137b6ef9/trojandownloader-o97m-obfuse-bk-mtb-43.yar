rule TrojanDownloader_O97M_Obfuse_BK_MTB_43{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4b 6f 6c 65 73 74 65 72 2e 76 62 73 22 } 		$a_01_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 48 65 6c 70 6f 74 2e 76 62 73 22 } 		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 42 69 6c 6f 64 65 72 2e 4d 6f 6e 74 65 6c 61 72 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 29 } 		$a_01_3 = {2e 45 78 65 63 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}