rule TrojanDownloader_O97M_Obfuse_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 49 42 53 59 5f 61 6c 34 6d 79 73 64 44 31 72 4d 4a 4a 4c 38 75 5f 47 58 65 65 5f 4b 6a 6e 67 4e 4d 5a 72 } 		$a_01_1 = {5a 53 20 3d 20 5a 53 20 26 20 } 		$a_01_2 = {6a 5f 5f 5f 68 20 3d 20 43 68 72 28 6e 5f 5f 5f 6f 20 2d 20 37 37 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}