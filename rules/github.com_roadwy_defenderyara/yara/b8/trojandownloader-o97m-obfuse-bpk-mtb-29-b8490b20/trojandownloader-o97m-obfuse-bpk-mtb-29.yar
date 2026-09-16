rule TrojanDownloader_O97M_Obfuse_BPK_MTB_29{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 62 6a 2e 20 5f 90 0c 02 00 4d 61 69 6e 43 61 6c 6c 65 78 2e 20 5f 90 0c 02 00 52 75 6e 20 5f 90 0c 02 00 64 64 2c 20 30 } 		$a_03_1 = {44 69 6d 20 6f 62 6a 20 41 73 20 4e 65 77 20 43 6c 61 73 73 32 90 0c 02 00 20 20 20 20 6f 62 6a 2e 20 5f 90 0c 02 00 20 20 20 20 47 65 74 4d 6f 72 65 4d 6f 64 75 6c 65 20 28 64 64 31 20 2b 20 64 64 32 20 2b 20 64 64 33 29 } 		$a_01_2 = {63 2e 41 64 64 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 61 73 64 61 73 64 71 77 66 65 66 77 65 66 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}