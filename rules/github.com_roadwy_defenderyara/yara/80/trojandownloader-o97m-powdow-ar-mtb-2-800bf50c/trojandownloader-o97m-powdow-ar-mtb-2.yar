rule TrojanDownloader_O97M_Powdow_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {27 6f 63 69 2e 6e 6f 63 69 76 61 66 2f 31 30 30 39 3a 39 35 2e 38 34 31 2e 30 30 31 2e 38 39 31 2f 2f 3a 70 74 74 68 27 28 65 6c 69 46 64 61 6f 6c 6e 77 6f 44 2e 29 } 		$a_01_1 = {6c 6c 65 68 73 72 65 77 6f 70 20 63 2f 20 65 78 65 2e 64 6d 63 } 		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 28 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}