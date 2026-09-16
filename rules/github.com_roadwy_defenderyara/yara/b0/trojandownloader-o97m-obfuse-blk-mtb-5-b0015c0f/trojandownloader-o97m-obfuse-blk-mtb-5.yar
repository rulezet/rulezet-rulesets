rule TrojanDownloader_O97M_Obfuse_BLK_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_3 = {3d 20 48 67 59 6c 5f 44 76 35 5f 4f 61 69 5f 37 33 53 2e 48 6e 67 57 6e 71 4b 57 53 57 39 } 		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 44 6e 6b 69 33 65 78 4f 75 46 67 4c 6d 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}