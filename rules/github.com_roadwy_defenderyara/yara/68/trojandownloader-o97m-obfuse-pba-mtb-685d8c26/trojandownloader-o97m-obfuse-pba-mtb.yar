rule TrojanDownloader_O97M_Obfuse_PBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } 		$a_01_1 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 68 74 74 70 3a 2f 2f 6d 61 69 6c 69 63 69 6f 75 73 2e 63 6f 6d 2f 66 69 6c 65 6d 61 6e 61 67 65 72 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 5c 66 69 6c 65 6d 61 6e 61 67 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}