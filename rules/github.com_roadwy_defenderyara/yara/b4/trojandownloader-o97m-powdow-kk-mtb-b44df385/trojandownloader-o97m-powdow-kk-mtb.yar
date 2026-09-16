rule TrojanDownloader_O97M_Powdow_KK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.KK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6c 69 73 74 62 6f 78 50 61 73 74 65 43 6f 75 6e 74 65 72 2e 68 74 61 22 } 		$a_01_1 = {6d 65 6d 49 6e 64 65 78 2e 65 78 65 63 20 70 28 72 6d 29 } 		$a_01_2 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 72 6d 29 2c 20 22 20 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}