rule TrojanDownloader_O97M_Obfuse_BTK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 } 		$a_01_3 = {66 41 75 70 44 50 30 39 5a 67 70 4e 2e 6b 6a 62 58 5f 32 5a 55 4e 5f 73 55 49 } 		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 58 47 4e 30 30 68 63 64 48 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}