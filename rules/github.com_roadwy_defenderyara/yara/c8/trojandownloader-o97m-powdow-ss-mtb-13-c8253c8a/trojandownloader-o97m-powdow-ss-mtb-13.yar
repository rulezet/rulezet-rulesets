rule TrojanDownloader_O97M_Powdow_SS_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 28 [0-07] 4d 5f 53 4f 69 4d 29 } 		$a_01_1 = {3d 20 22 68 74 61 22 } 		$a_01_2 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 72 69 76 69 65 72 61 64 65 73 61 6f 6c 6f 75 2e 63 6f 6d 2e 62 72 2f } 		$a_01_3 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f } 		$a_01_4 = {3d 20 22 22 22 6d 73 } 		$a_01_5 = {3d 20 22 68 74 61 22 22 20 68 74 22 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}