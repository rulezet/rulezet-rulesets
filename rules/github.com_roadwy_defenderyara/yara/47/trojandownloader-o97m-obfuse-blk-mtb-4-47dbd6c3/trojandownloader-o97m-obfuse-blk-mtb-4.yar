rule TrojanDownloader_O97M_Obfuse_BLK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 62 67 74 4a 6a 5f 55 69 48 37 5f 6a 6d 50 2e 50 73 7a 58 73 5f 47 57 6b 4e } 		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 45 45 62 70 6d 5f 44 33 71 5f 32 5a 59 36 5f 57 41 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}