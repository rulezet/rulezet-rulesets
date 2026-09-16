rule TrojanDownloader_O97M_Obfuse_SU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 61 67 65 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } 		$a_01_1 = {61 67 65 73 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 28 6b 6f 6c 61 29 } 		$a_01_2 = {6e 61 6d 65 20 3d 20 22 5c 5c 22 20 26 20 6e 61 6d 65 20 26 20 22 2e 6a 73 65 } 		$a_01_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}