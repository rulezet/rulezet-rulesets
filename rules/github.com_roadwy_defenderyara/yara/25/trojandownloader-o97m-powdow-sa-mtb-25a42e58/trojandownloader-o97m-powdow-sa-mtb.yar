rule TrojanDownloader_O97M_Powdow_SA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 61 72 69 6e 67 61 72 65 73 65 72 76 61 73 2e 63 6f 6d 2e 62 72 2f } 		$a_03_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 [0-79] 6c 6f 63 61 6c 68 6f 73 74 20 26 20 22 20 26 20 50 53 68 65 6c 6c 43 6f 64 65 2c 20 76 62 48 69 64 65 } 		$a_01_2 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}