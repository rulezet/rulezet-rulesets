rule TrojanDownloader_O97M_Powdow_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f 6a 6a 66 49 51 38 75 27 2c 27 70 64 } 		$a_01_1 = {27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 } 		$a_01_2 = {6f 77 65 72 73 68 65 5e 6c 5e 6c 20 2d 77 20 31 } 		$a_01_3 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 70 } 		$a_01_4 = {62 61 74 27 29 2e 42 2e 6e 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}