rule TrojanDownloader_O97M_Obfuse_KC{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KC,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 23 28 [0-60] 43 65 6c 6c 73 28 } 		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 28 } 		$a_01_2 = {41 73 63 28 4d 69 64 24 28 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}