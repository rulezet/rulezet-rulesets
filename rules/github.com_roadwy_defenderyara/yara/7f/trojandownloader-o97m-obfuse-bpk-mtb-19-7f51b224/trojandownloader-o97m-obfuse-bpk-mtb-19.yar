rule TrojanDownloader_O97M_Obfuse_BPK_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BPK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 65 69 6e 6b 6f 6e 68 75 6e 31 2e 45 58 45 43 20 6c 69 73 74 65 6e 31 20 2b 20 6d 61 64 61 72 32 20 2b 20 6a 61 6e 75 33 20 2b 20 6a 61 6e 75 34 20 2b 20 66 61 6b 69 72 34 } 		$a_01_1 = {53 65 74 20 6d 65 69 6e 6b 6f 6e 68 75 6e 31 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 22 20 2b 20 45 6e 44 65 63 72 79 70 74 4d 55 52 } 		$a_01_2 = {66 61 6b 69 72 34 20 3d 20 45 6e 44 65 63 72 79 70 74 4d 55 52 28 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}