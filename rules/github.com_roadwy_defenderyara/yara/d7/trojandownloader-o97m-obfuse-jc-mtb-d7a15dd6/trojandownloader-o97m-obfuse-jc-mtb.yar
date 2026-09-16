rule TrojanDownloader_O97M_Obfuse_JC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 61 6e 61 6e 61 61 72 65 73 74 73 69 67 69 72 69 79 61 2e 63 6f 6d 2f 79 74 70 71 61 78 77 71 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } 		$a_01_1 = {43 3a 5c 46 65 74 69 6c 5c 47 69 6f 6c 61 5c 6f 63 65 61 6e 44 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}