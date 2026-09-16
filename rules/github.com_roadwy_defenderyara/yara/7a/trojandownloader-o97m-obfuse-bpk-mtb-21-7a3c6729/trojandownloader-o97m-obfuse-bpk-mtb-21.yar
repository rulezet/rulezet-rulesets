rule TrojanDownloader_O97M_Obfuse_BPK_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6f 62 6a 2e 4a 61 6e 75 67 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 75 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 65 79 77 75 69 71 64 62 6e 61 6d 73 64 67 6a 68 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } 		$a_01_1 = {53 65 74 20 4a 61 6e 75 67 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 20 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}