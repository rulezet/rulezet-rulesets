rule TrojanDownloader_O97M_Obfuse_EO{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EO,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {44 69 6d 20 [0-20] 20 41 73 20 43 75 72 72 65 6e 63 79 } 		$a_02_1 = {53 74 72 52 65 76 65 72 73 65 28 53 74 72 52 65 76 65 72 73 65 28 [0-20] 28 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}