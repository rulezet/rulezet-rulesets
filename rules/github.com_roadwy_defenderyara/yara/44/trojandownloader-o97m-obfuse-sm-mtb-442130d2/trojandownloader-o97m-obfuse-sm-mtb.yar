rule TrojanDownloader_O97M_Obfuse_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } 		$a_01_1 = {3d 20 6f 74 68 65 72 20 26 20 22 5c 7a 78 2e 65 78 65 22 } 		$a_01_2 = {70 75 74 73 20 3d 20 53 70 6c 69 74 28 6f 75 66 66 65 72 2c 20 22 26 22 29 } 		$a_01_3 = {43 42 79 74 65 28 28 22 26 48 22 20 26 20 70 75 74 73 28 69 6e 66 6f 29 29 20 58 6f 72 20 26 48 46 46 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}