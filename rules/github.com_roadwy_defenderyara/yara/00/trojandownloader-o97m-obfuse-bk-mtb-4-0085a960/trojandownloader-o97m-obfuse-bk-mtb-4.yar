rule TrojanDownloader_O97M_Obfuse_BK_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a 75 51 6b 51 78 75 4e 62 35 44 5f 52 57 2e 6f 69 4b 70 4a 58 48 47 41 74 64 5a 59 52 68 57 6e 35 35 44 } 		$a_01_1 = {6d 78 63 5f 65 72 20 3d 20 43 68 72 28 6e 76 20 2d 20 36 34 29 } 		$a_01_2 = {2e 52 75 6e 28 } 		$a_01_3 = {6b 4a 20 3d 20 6b 4a 20 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}