rule TrojanDownloader_O97M_Emotet_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4e 65 78 74 90 0c 02 00 44 6f 20 57 68 69 6c 65 20 [0-15] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } 		$a_03_1 = {22 73 3a 57 [0-09] 69 [0-09] 6e [0-12] 33 [0-12] 32 [0-12] 5f [0-12] 20 2b 20 } 		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } 		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}