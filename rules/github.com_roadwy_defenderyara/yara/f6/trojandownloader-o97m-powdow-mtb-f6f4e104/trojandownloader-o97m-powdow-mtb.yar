rule TrojanDownloader_O97M_Powdow_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 30 2c 20 22 68 74 74 70 3a 2f 2f 77 66 70 79 75 74 66 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 74 7a 65 33 2e 63 61 62 22 2c 20 22 31 2e 65 78 70 22 2c 20 30 2c 20 30 29 } 		$a_01_1 = {2e 72 75 6e 20 22 72 65 67 73 76 72 33 32 20 31 2e 65 78 70 22 } 		$a_01_2 = {22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}