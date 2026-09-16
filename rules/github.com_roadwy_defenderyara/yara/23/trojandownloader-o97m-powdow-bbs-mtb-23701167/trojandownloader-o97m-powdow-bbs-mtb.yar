rule TrojanDownloader_O97M_Powdow_BBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 63 76 67 6b 6a 77 47 33 34 37 72 74 48 44 46 46 47 65 34 36 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 20 26 20 68 72 6b 77 64 6a 6b 73 64 6a 62 6b 2c 20 30 } 		$a_01_1 = {3d 20 43 65 6c 6c 73 28 73 64 66 67 68 61 73 64 41 53 66 48 53 64 72 74 73 79 67 34 36 73 64 72 67 61 73 64 66 2c 20 63 64 76 67 6e 66 68 61 69 77 75 65 74 34 75 54 68 53 64 47 33 34 74 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}