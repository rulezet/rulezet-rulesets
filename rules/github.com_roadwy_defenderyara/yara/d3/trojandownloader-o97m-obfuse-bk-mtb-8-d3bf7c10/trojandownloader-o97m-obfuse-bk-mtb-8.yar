rule TrojanDownloader_O97M_Obfuse_BK_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 5f 5f 32 37 6a 57 74 32 2e 79 5f 4f 71 77 44 39 4f 61 61 6b 5f 54 4b 4b 41 4a 77 68 6b } 		$a_01_1 = {68 6a 64 61 20 3d 20 43 68 72 28 64 73 20 2d 20 33 30 29 } 		$a_01_2 = {2e 52 75 6e 28 4c 57 56 6f 5a 69 42 5a 5f 4e 5f 2c 20 48 33 6c 65 58 67 73 79 4b 59 5f 45 79 54 6d 63 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}