rule TrojanDownloader_O97M_Obfuse_BK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 4c 5f 45 48 78 6d 57 7a 5f 56 43 44 5f 44 77 58 57 6f 2e 4c 67 5f 4f 5f 71 66 4f 4b 65 5a 68 61 47 68 46 4a 47 66 51 6c 48 74 42 35 } 		$a_01_1 = {67 66 5f 39 20 3d 20 43 68 72 28 61 73 5f 77 20 2d 20 34 33 29 } 		$a_01_2 = {2e 52 75 6e 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}