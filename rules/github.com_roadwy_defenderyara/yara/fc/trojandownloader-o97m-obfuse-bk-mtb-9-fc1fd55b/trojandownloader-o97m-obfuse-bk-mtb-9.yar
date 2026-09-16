rule TrojanDownloader_O97M_Obfuse_BK_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 62 51 5a 72 6e 38 49 34 4b 5f 5a 35 33 5f 4a 55 78 53 4d 4f 75 4f 70 33 38 7a 39 5f 2e 6a 74 73 67 39 76 50 5f 36 6a 37 44 49 6f 4a 6e 48 6d 45 69 48 34 50 61 4d } 		$a_01_1 = {6d 6b 5f 6c 6c 20 3d 20 43 68 72 28 68 66 20 2d 20 36 31 29 } 		$a_01_2 = {54 54 20 3d 20 54 54 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}