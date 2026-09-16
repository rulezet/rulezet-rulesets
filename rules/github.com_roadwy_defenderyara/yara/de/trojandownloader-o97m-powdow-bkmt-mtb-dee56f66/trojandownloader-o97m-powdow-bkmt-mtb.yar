rule TrojanDownloader_O97M_Powdow_BKMT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKMT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 74 77 67 20 3d 20 6f 74 77 67 20 26 20 } 		$a_01_1 = {2e 52 75 6e 28 77 6a 74 74 61 77 75 6f 6f 61 78 6a 6b 63 6b 2c 20 64 6b 6e 74 6c 67 6b 74 70 73 64 6b 74 66 75 29 } 		$a_01_2 = {3d 20 43 68 72 28 66 73 63 76 20 2d 20 31 32 31 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}