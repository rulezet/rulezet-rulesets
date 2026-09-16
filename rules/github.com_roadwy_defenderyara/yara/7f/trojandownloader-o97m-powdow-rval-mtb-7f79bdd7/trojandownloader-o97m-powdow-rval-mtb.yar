rule TrojanDownloader_O97M_Powdow_RVAL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 20 5f 0d 0a 28 70 69 6e 67 73 29 } 		$a_01_1 = {4b 41 52 54 49 43 20 3d 20 22 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } 		$a_03_2 = {4c 47 20 3d 20 22 [0-01] 68 74 74 70 73 22 } 		$a_01_3 = {54 20 3d 20 54 41 65 63 20 2b 20 54 59 69 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}