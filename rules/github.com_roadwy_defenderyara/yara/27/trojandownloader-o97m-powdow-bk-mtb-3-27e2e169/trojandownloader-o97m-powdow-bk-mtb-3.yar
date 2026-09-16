rule TrojanDownloader_O97M_Powdow_BK_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 78 2c 20 22 62 62 6e 6e 65 64 65 74 63 79 22 2c 20 22 22 29 } 		$a_01_1 = {3d 20 41 63 74 69 76 65 43 65 6c 6c 2e 4f 66 66 73 65 74 28 69 43 2c 20 31 29 2e 56 61 6c 75 65 } 		$a_01_2 = {43 61 6c 6c 20 79 47 47 73 76 61 42 2e 70 6b 75 74 64 46 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}