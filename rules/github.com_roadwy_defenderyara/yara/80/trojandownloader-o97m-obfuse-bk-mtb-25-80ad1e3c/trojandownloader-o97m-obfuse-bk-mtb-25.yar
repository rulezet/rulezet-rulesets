rule TrojanDownloader_O97M_Obfuse_BK_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 62 5f 5f 5f 76 28 64 73 20 41 73 20 49 6e 74 65 67 65 72 29 } 		$a_01_1 = {69 4b 6a 58 79 78 4e 67 50 55 5a 58 2e 43 69 75 7a 69 74 4f 4b 54 45 62 4f 67 6a 4d 36 5f 59 56 5f 6e 47 53 6b 76 6d 37 5f 79 } 		$a_01_2 = {2e 52 75 6e 28 77 4f 5f 50 44 71 47 57 52 59 67 58 7a 36 36 39 75 62 59 7a 6a 5f 4e 4d 4e 61 57 73 4d 53 45 31 31 58 65 77 33 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}