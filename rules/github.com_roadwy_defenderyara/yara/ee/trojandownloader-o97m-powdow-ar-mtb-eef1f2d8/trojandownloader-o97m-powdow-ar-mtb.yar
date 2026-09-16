rule TrojanDownloader_O97M_Powdow_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {58 46 42 70 59 33 52 31 63 6d 56 7a 58 47 68 6f 62 6e 70 75 59 6d 4a 6d 59 53 35 6c 65 47 56 39 } 		$a_00_1 = {4c 79 38 78 4f 43 34 78 4f 54 59 75 4d 54 55 33 4c 6a 67 32 4c 31 51 76 4d 7a 41 30 4d 54 41 77 4d 43 35 71 63 47 63 67 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}