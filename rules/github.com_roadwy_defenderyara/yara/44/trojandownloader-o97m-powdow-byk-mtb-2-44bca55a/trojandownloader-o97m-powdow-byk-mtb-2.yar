rule TrojanDownloader_O97M_Powdow_BYK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 4b 38 50 71 2e 45 59 4c 45 4c 70 63 74 77 33 64 51 58 64 54 41 5f 6e 5f 66 } 		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } 		$a_01_2 = {2e 52 75 6e 28 4c 67 39 36 36 61 5f 38 44 56 2c 20 63 6b 46 5f 77 5f 68 61 6f 6b 31 42 32 5f 4a 4e 37 6f 4f 31 73 6c 4a 74 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}