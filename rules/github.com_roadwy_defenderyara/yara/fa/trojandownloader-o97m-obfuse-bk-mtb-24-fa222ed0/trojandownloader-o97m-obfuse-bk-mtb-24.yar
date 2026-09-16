rule TrojanDownloader_O97M_Obfuse_BK_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 33 56 33 4f 4f 62 72 64 31 72 5f 6c 34 6d 6c 38 37 75 63 54 56 41 78 62 72 71 2e 79 61 41 79 75 52 4d 79 44 38 59 5a 76 42 5f 69 6b 59 6e 35 } 		$a_01_1 = {44 5f 5f 53 20 3d 20 43 68 72 28 53 41 20 2d 20 31 30 30 29 } 		$a_01_2 = {2e 52 75 6e 28 50 62 62 6e 5a 5f 5f 4b 68 53 41 4d 54 33 48 5f 6e 6c 35 7a 39 77 77 51 4b 63 49 75 44 4d 55 47 6b 72 77 7a 32 68 43 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}