rule TrojanDownloader_O97M_Obfuse_BK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 79 73 5f 69 2e 75 4e 50 5f 66 5f 6b 5f 75 67 64 4a 62 5f 6b 39 46 48 6b 6a } 		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } 		$a_01_2 = {2e 52 75 6e 28 6d 72 44 5f 52 5f 61 4c 75 65 46 34 2c 20 76 42 5a 5f 5f 5f 6a 55 34 4b 50 55 54 77 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}