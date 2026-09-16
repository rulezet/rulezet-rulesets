rule TrojanDownloader_O97M_Obfuse_BK_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 77 57 6e 74 51 77 64 64 59 6e 78 75 76 5a 69 5a 73 5f 36 54 33 2e 75 5f 58 48 74 54 4d 61 76 46 69 6d 54 62 45 4e 51 4c 4e 75 41 7a 4a 42 4e 41 35 53 52 } 		$a_01_1 = {68 5f 75 69 6b 20 3d 20 43 68 72 28 76 66 20 2d 20 35 30 29 } 		$a_01_2 = {2e 52 75 6e 28 6b 66 4a 68 38 4e 39 42 73 4a 69 51 36 6a 51 73 39 72 52 67 6e 53 50 64 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}