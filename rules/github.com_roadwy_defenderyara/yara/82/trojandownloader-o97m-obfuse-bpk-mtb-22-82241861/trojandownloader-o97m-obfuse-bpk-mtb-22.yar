rule TrojanDownloader_O97M_Obfuse_BPK_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 74 61 6c 61 74 75 77 61 31 20 2b 20 74 61 6c 61 74 75 77 61 32 20 2b 20 74 61 6c 61 74 75 77 61 33 20 2b 20 74 61 6c 61 74 75 77 61 34 20 2b 20 74 61 6c 61 74 75 77 61 35 } 		$a_01_1 = {3d 20 22 68 22 20 26 20 48 6f 6e 65 79 20 2b 20 61 6e 69 6d 61 6c 32 20 2b 20 53 74 72 69 6e 67 28 32 2c 20 22 2f 22 29 20 2b 20 5a 75 6d 61 20 26 20 22 6a 2e 22 20 2b 20 73 6e 61 6b 65 20 2b 20 53 74 72 69 6e 67 28 33 2c 20 22 68 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}