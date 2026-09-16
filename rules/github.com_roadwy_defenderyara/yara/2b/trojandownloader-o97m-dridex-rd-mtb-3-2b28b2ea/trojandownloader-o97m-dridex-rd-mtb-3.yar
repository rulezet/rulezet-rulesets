rule TrojanDownloader_O97M_Dridex_RD_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Dridex.RD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 6f 20 26 20 63 68 61 6f 5f 73 28 5a 2c 20 4d 69 64 28 65 2c 20 6d 6b 2c 20 76 29 29 } 		$a_01_1 = {3d 20 53 70 6c 69 74 28 6f 6f 2c 20 61 72 65 61 63 6c 69 65 6e 74 6f 29 } 		$a_01_2 = {28 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 22 20 26 20 52 65 70 6c 61 63 65 28 4f 2c 20 6d 69 6c 6f 77 5f 73 2c 20 72 65 70 6f 72 74 5f 72 65 70 29 29 2c 20 31 2c 20 32 29 } 		$a_01_3 = {3d 20 43 68 72 28 41 73 63 28 73 29 20 2b 20 67 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}