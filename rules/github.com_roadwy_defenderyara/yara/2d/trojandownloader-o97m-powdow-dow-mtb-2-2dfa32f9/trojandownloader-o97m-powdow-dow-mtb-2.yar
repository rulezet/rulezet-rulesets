rule TrojanDownloader_O97M_Powdow_DOW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DOW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_1 = {70 5e 6f 77 5e 65 72 73 68 65 6c 6c 20 2d 77 } 		$a_01_2 = {49 6e 76 6f 6b 65 22 22 28 27 68 74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 63 73 66 79 77 64 27 2c 27 70 64 2e 62 61 74 27 29 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}