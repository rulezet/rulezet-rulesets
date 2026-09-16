rule TrojanDownloader_O97M_Obfuse_BPK_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 65 20 68 74 74 70 3a 2f 2f 61 63 68 6f 74 65 69 73 2e 63 6f 6d 2e 62 72 2f 69 6d 61 67 65 73 2f 61 74 65 6e 64 69 6d 65 6e 74 6f 2e 74 78 74 22 } 		$a_01_1 = {3d 20 57 6d 64 6d 65 31 20 2b 20 57 6d 64 6d 65 32 20 2b 20 57 6d 64 6d 65 33 20 2b 20 57 6d 64 6d 65 34 20 2b 20 57 6d 64 6d 65 35 20 2b 20 57 6d 64 6d 65 35 31 } 		$a_01_2 = {53 68 65 6c 6c 20 28 57 6d 64 6d 65 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}