rule TrojanDownloader_O97M_Powdow_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 5e 77 65 72 73 68 } 		$a_01_1 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } 		$a_01_2 = {74 74 70 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f 27 2c 27 61 2e 62 61 74 27 29 } 		$a_01_3 = {74 74 70 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 35 6f 6e 6e 63 6e 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}