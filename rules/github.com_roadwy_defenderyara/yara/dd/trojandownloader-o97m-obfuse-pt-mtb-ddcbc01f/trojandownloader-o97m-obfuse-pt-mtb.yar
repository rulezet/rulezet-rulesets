rule TrojanDownloader_O97M_Obfuse_PT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2e 63 6f 6d 2e 62 72 2f 90 0a 3c 00 3d 20 22 4d 53 48 54 41 20 (68 74 74 70|68 74 74 70 73) 3a 2f 2f 6d 61 72 69 6e 67 61 72 65 73 65 72 76 61 73 } 		$a_00_1 = {53 68 65 6c 6c 20 28 56 61 72 29 } 		$a_00_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}