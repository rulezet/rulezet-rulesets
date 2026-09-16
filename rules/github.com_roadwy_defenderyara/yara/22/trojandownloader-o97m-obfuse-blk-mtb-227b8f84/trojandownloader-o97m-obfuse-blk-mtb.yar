rule TrojanDownloader_O97M_Obfuse_BLK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BLK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } 		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } 		$a_01_2 = {3d 20 43 61 75 54 74 73 32 73 2e 56 53 76 77 63 33 4c } 		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 4a 44 4c 33 77 68 6d 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}