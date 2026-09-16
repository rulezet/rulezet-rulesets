rule TrojanDownloader_O97M_Powdow_TNY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.TNY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 5e 77 65 72 5e 73 68 65 6c 6c 20 2d 77 } 		$a_01_1 = {28 27 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_2 = {49 6e 76 6f 6b 65 28 28 27 68 74 27 2b 27 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 36 74 63 64 39 36 74 27 29 2c 27 6b 63 2e 65 78 65 27 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}