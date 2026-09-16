rule TrojanDownloader_O97M_Obfuse_JL_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 22 20 2b 20 22 53 22 20 2b 20 22 63 22 20 2b 20 22 72 69 70 74 2e 53 68 65 6c 6c } 		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 28 22 22 22 64 27 2a 27 6b 6c 69 69 69 6a 6a 6b 69 6a 6c 69 6c 69 6c 27 2a 27 64 27 2a 27 64 5c 70 27 2a 27 2e 6a 5c 5c 3a 70 74 74 68 22 22 22 22 61 74 68 73 27 2a 27 22 22 22 29 } 		$a_01_2 = {52 65 70 6c 61 63 65 28 57 65 62 55 72 6c 2c 20 22 27 2a 27 22 2c 20 22 6d 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}