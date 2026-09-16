rule TrojanDownloader_O97M_Obfuse_BK_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 48 76 55 52 50 49 38 34 6b 50 35 5f 2e 6f 54 6b 48 36 5a 49 34 45 4f 75 5a 4b 33 72 5f 74 4f 5a 4c } 		$a_01_1 = {44 5f 5f 53 20 3d 20 43 68 72 28 53 41 20 2d 20 31 30 30 29 } 		$a_01_2 = {2e 52 75 6e 28 6a 6c 77 4a 71 57 48 38 7a 34 39 49 78 52 47 4d 33 54 6f 45 75 62 53 44 63 38 6b 67 5f 5a 4b 77 6e 4e 4d 67 77 75 57 67 57 67 57 31 6a 42 31 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}