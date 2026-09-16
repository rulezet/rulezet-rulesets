rule TrojanDownloader_O97M_Powdow_TNY_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 70 6f 77 65 5e 72 73 68 65 6c 6c 20 2d 77 20 31 20 28 6e 45 77 2d 6f 42 6a 65 60 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } 		$a_01_1 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_2 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 72 62 2e 67 79 2f 67 36 34 62 77 6a 27 2c 27 73 68 2e 65 78 65 27 29 } 		$a_01_3 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 72 62 2e 67 79 2f 67 6c 79 77 65 76 27 2c 27 64 65 2e 65 78 65 27 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}