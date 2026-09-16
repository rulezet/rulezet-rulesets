rule TrojanDownloader_O97M_Obfuse_BPK_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 25 38 32 33 34 25 38 32 33 34 40 6a 2e 6d 70 2f 64 64 6b 73 6c 61 73 64 6a 61 6c 73 6a 64 61 73 6e 77 22 } 		$a_01_1 = {53 68 65 6c 6c 20 6d 79 43 68 72 79 73 6c 65 72 20 2b 20 53 69 73 74 65 72 73 52 61 6e 67 65 52 6f 76 65 72 } 		$a_01_2 = {3a 20 53 68 65 6c 6c 20 64 65 63 72 79 70 74 28 22 76 6f 74 6d 22 2c 20 22 36 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}