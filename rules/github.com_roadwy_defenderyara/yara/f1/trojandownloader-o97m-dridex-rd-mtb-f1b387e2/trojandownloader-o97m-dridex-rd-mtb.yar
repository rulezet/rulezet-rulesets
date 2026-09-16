rule TrojanDownloader_O97M_Dridex_RD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 46 69 6e 64 28 57 68 61 74 3a 3d 22 2a 22 2c 20 4c 6f 6f 6b 49 6e 3a 3d 78 6c 56 61 6c 75 65 73 } 		$a_01_1 = {20 3d 20 53 70 6c 69 74 28 6a 69 2c 20 22 21 22 29 } 		$a_01_2 = {26 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 52 65 70 6c 61 63 65 28 61 2c 20 22 3f 22 2c 20 65 29 29 2c 20 31 2c 20 31 29 } 		$a_01_3 = {20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 61 2c 20 69 2c 20 31 29 29 20 2b 20 32 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}