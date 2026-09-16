rule TrojanDownloader_O97M_Powdow_BYK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 68 35 5f 5f 36 38 35 2e 7a 54 59 4a 6c 54 33 5a 71 53 6a 61 62 56 56 46 56 48 48 61 } 		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } 		$a_01_2 = {2e 52 75 6e 28 52 6f 6f 75 47 67 5f 54 53 5a 71 5f 70 79 64 76 65 4f 54 5a 2c 20 52 5f 5f 63 31 42 35 75 4d 34 63 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}