rule TrojanDownloader_O97M_Powdow_BB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 70 6c 61 63 65 28 22 57 60 37 63 72 69 70 74 2e 60 37 68 65 6c 6c 22 2c 20 22 60 37 22 2c 20 22 73 22 29 29 } 		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 70 6f 77 60 37 72 73 68 60 37 6c 6c 20 22 2c 20 22 60 37 22 2c 20 22 65 22 29 } 		$a_01_2 = {48 31 48 39 2e 52 75 6e 20 28 48 34 48 36 20 2b 20 48 32 48 36 29 2c 20 30 2c 20 54 72 75 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}