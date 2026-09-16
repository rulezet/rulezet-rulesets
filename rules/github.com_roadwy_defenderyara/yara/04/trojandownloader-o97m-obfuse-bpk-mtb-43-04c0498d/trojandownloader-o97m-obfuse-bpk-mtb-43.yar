rule TrojanDownloader_O97M_Obfuse_BPK_MTB_43{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 20 20 28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 20 5f } 		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 5f 0d 0a 4c 69 62 20 5f 0d 0a 22 53 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 5f 0d 0a 41 6c 69 61 73 20 5f 0d 0a 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 5f } 		$a_01_2 = {53 57 5f 53 48 4f 57 4d 69 6e 69 6d 69 7a 65 29 } 		$a_01_3 = {22 25 70 75 62 6c 69 63 25 22 20 5f } 		$a_01_4 = {6b 6f 6b 6f 20 5f 0d 0a 3d 20 5f 0d 0a 22 6d 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 73 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 68 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 74 22 20 5f 0d 0a 2b 20 5f 0d 0a 22 61 22 0d 0a 45 6e 64 20 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}