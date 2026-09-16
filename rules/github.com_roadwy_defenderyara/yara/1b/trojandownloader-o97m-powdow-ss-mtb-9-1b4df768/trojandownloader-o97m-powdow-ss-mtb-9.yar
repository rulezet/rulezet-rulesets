rule TrojanDownloader_O97M_Powdow_SS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 38 32 33 34 25 38 32 33 34 40 6a 2e 6d 70 2f 64 64 6b 6a 61 73 70 6f 71 77 69 6f 6b 61 73 6c 6b 64 6b 77 } 		$a_01_1 = {53 68 65 6c 6c 20 64 65 63 72 79 70 74 28 22 76 6f 74 6d 22 2c 20 22 36 22 29 } 		$a_01_2 = {6d 79 43 68 72 79 73 6c 65 72 20 3d 20 64 65 63 72 79 70 74 28 22 72 22 2c 20 22 35 22 29 20 2b } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}