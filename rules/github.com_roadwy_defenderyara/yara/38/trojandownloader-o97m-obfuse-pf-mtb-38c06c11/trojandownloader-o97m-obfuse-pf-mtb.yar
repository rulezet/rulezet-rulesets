rule TrojanDownloader_O97M_Obfuse_PF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 		$a_00_1 = {53 68 65 6c 6c 20 28 76 61 72 29 } 		$a_02_2 = {2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f 90 0a 3c 00 3d 20 22 6d 73 68 54 41 20 (68 74 74 70|68 74 74 70 73) 3a 2f 2f 74 72 61 6e 73 76 61 6c 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}