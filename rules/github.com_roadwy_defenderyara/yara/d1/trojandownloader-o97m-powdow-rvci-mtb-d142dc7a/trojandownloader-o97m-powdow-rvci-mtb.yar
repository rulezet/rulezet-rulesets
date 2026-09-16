rule TrojanDownloader_O97M_Powdow_RVCI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 24 63 3b 22 2c 76 62 68 69 64 65 29 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 73 75 62 } 		$a_01_1 = {39 69 63 64 6f 64 68 72 77 6f 69 38 76 62 77 39 75 62 33 62 76 62 67 6c 68 7a 6e 6a 76 62 78 6c 76 64 73 35 79 64 73 39 6b 62 33 64 75 62 67 39 68 7a 63 38 79 6c 6d 76 34 7a 73 } 		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}