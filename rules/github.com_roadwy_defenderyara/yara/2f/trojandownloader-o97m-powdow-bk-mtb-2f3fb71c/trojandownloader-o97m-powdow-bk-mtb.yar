rule TrojanDownloader_O97M_Powdow_BK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } 		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } 		$a_01_2 = {74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 38 6a 6d 44 50 56 62 } 		$a_01_3 = {6d 6f 76 65 2d 49 74 65 6d 20 2d 50 61 74 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}