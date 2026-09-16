rule TrojanDownloader_O97M_Powdow_BYK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BYK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 79 4b 46 5f 2e 72 4a 5f 70 5f 38 6c 69 6c 33 52 70 71 4f 76 76 5f 4f 5f 57 } 		$a_01_1 = {64 5f 5f 5f 66 73 61 20 3d 20 43 68 72 28 73 5f 5f 64 20 2d 20 32 32 29 } 		$a_01_2 = {2e 52 75 6e 28 70 4d 54 76 5f 37 43 32 66 59 6a 4e 2c 20 74 5f 4f 57 4a 47 78 45 37 66 64 46 78 72 5f 74 5f 74 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}