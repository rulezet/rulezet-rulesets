rule TrojanDownloader_O97M_Obfuse_PDR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 28 22 63 75 72 6c 20 68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 6f 6b 69 71 2e 62 73 6e 6c 2e 63 6f 2e 69 6e 2f 64 61 74 61 5f 65 6e 74 72 79 2f 63 69 72 63 75 6c 61 72 73 2f 6d [0-05] 61 [0-05] 63 2e 65 78 65 } 		$a_01_1 = {53 68 65 6c 6c 20 28 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 61 2e 65 78 65 22 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}