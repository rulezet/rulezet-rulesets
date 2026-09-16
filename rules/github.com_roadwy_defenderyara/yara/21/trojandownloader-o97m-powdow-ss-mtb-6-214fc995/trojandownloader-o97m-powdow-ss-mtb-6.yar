rule TrojanDownloader_O97M_Powdow_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 74 65 72 63 61 2e } 		$a_03_1 = {53 68 65 6c 6c 20 28 [0-05] 4d 5f 53 4f 69 4d 29 } 		$a_01_2 = {3d 20 22 68 74 61 22 } 		$a_01_3 = {3d 20 22 68 74 61 22 22 20 68 74 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}