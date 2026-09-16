rule TrojanDownloader_O97M_Powdow_SS_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 65 78 70 6c 6f 72 65 72 22 2c 20 [0-15] 2c 20 22 22 2c 20 31 29 } 		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29 } 		$a_01_2 = {26 20 22 20 2d 77 20 68 69 20 73 5e 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 6a 6b 6c 61 69 72 65 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 7a 61 2d 61 64 6d 69 6e 2f 6d 61 6e 6e 67 65 72 2f 74 6f 64 61 79 2e 65 60 78 65 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}