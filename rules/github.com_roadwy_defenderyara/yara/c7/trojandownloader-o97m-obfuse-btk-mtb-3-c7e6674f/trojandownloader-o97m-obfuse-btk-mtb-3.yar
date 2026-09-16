rule TrojanDownloader_O97M_Obfuse_BTK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BTK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_3 = {3d 20 44 74 6a 77 39 5f 63 39 75 52 5f 71 4c 6e 66 5f 76 71 69 2e 6e 42 58 59 4d 33 54 } 		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 45 69 62 49 32 30 30 34 36 43 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}