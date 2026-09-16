rule TrojanDownloader_O97M_Obfuse_BK_MTB_37{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 42 6c 6f 62 65 72 73 2e 76 62 73 22 } 		$a_01_1 = {53 65 74 20 4d 61 6d 74 65 72 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 73 65 72 46 6f 72 6d 31 2e 54 61 67 29 } 		$a_01_2 = {4d 61 6d 74 65 72 73 2e 45 78 65 63 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 54 61 67 } 		$a_01_3 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 46 45 72 69 6f 2e 76 62 73 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}