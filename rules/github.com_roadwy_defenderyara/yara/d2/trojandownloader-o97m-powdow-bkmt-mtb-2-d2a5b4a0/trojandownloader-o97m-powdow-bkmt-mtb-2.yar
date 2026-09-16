rule TrojanDownloader_O97M_Powdow_BKMT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 64 34 35 63 76 76 30 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } 		$a_01_1 = {3d 20 47 78 68 74 4b 45 6d 28 42 61 56 75 2c 20 6c 4c 53 55 29 } 		$a_01_2 = {42 4b 4a 61 48 66 45 2e 4e 61 6d 65 20 3d 20 22 43 6f 6d 6d 65 6e 74 73 22 20 54 68 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}