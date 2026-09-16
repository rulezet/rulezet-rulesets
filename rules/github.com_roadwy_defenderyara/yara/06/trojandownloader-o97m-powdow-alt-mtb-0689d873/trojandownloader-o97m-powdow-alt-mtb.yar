rule TrojanDownloader_O97M_Powdow_ALT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 72 68 7a 6d 65 58 54 28 66 67 66 6a 68 66 67 66 67 2c 20 66 64 34 35 63 76 76 30 29 } 		$a_01_1 = {49 45 68 79 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 64 34 35 63 76 76 30 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } 		$a_01_2 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}