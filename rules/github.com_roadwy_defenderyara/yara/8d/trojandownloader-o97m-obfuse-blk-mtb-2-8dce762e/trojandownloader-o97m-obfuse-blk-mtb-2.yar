rule TrojanDownloader_O97M_Obfuse_BLK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 52 43 75 62 5f 4d 68 68 5f 78 59 41 6c 5f 37 77 54 2e 44 48 74 45 6f 6f 33 4a } 		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 67 6d 42 4a 70 5f 32 30 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}