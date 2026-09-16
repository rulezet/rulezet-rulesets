rule TrojanDownloader_O97M_Dridex_RD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 3d 52 45 22 3a 20 } 		$a_01_1 = {20 3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 45 2c 20 22 5b 22 2c 20 22 4a 22 29 3a 20 52 75 6e 20 28 6d 67 20 26 20 22 6f 5f 69 62 6e 32 22 29 } 		$a_01_2 = {20 3d 20 6d 67 20 26 20 22 6f 5f 69 62 6e 32 22 3a 20 63 20 3d 20 66 75 20 2b 20 66 75 20 2b 20 66 75 3a } 		$a_01_3 = {75 20 3d 20 75 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 6e 2c 20 58 2c 20 66 75 29 29 20 2b 20 6b 29 3a 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}