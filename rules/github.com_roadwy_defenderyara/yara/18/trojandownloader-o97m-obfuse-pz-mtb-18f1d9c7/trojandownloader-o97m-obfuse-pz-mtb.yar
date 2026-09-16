rule TrojanDownloader_O97M_Obfuse_PZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 [0-10] 28 [0-10] 2c 20 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-10] 2e 70 64 66 22 29 } 		$a_02_1 = {2b 20 22 73 76 72 33 32 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-10] 2e 70 64 66 22 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}