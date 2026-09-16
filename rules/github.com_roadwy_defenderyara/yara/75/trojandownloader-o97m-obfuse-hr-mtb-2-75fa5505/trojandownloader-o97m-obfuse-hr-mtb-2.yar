rule TrojanDownloader_O97M_Obfuse_HR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 		$a_03_1 = {2e 56 61 6c 75 65 29 2e 52 75 6e 25 20 [0-30] 28 32 29 20 2b 20 [0-30] 28 30 29 2c } 		$a_03_2 = {2e 52 75 6e 25 20 [0-20] 28 [0-14] 2e 43 6f 6e 74 72 6f 6c 73 2c 20 32 29 20 2b } 		$a_01_3 = {2e 43 6f 6e 74 72 6f 6c 73 } 		$a_01_4 = {3d 20 53 71 72 28 34 29 20 2d 20 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}