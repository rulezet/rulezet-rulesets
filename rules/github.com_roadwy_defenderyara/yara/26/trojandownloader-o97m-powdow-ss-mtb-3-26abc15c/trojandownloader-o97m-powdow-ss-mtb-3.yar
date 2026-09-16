rule TrojanDownloader_O97M_Powdow_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 37 36 64 34 77 61 67 } 		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_2 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}