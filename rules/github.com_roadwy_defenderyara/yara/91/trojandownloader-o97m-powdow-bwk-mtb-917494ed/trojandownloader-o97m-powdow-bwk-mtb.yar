rule TrojanDownloader_O97M_Powdow_BWK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BWK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 68 4b 77 20 2b 20 48 56 20 2b 20 62 68 68 7a 76 45 58 63 45 4b 69 20 2b 20 72 68 72 5a 73 57 79 4f 20 2b 20 52 45 73 6b 46 4d 45 6e 47 59 69 20 2b 20 5a 66 66 5a 46 44 44 4e 69 4b 20 2b 20 58 59 20 2b 20 6b 51 59 52 45 6e 43 69 54 73 42 20 2b 20 41 43 53 4a 45 61 42 4c 47 20 2b 20 63 4a 75 75 64 73 51 } 		$a_01_1 = {75 6b 2e 52 75 6e 20 4d 7a 51 44 4e 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}