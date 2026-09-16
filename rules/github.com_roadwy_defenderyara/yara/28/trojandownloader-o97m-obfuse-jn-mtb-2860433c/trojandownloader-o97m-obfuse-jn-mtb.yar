rule TrojanDownloader_O97M_Obfuse_JN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 73 63 6a 74 74 2e 66 72 2f 70 64 66 2f 74 65 73 74 2e 65 78 65 } 		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 44 6f 77 6e 6c 6f 61 64 73 5c 62 61 74 74 65 72 79 2e 65 78 65 } 		$a_01_2 = {53 68 65 6c 6c 28 44 65 73 74 69 6e 61 74 69 6f 6e 46 69 6c 65 2c 20 31 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}