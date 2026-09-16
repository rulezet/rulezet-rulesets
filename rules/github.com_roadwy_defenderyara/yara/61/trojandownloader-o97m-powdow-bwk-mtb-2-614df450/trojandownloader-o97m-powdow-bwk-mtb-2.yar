rule TrojanDownloader_O97M_Powdow_BWK_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BWK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 55 48 4c 51 66 54 48 47 54 45 20 2b 20 43 4a 50 54 20 2b 20 72 7a 58 63 55 20 2b 20 58 56 65 65 61 51 73 20 2b 20 52 4c 74 74 64 79 52 44 42 61 73 20 2b 20 4c 42 45 46 66 20 2b 20 70 6b 66 77 58 51 72 20 2b 20 47 69 4d 4e 69 42 53 4e 56 4d 73 20 2b 20 56 47 6e 4e 69 56 20 2b 20 68 48 20 2b } 		$a_01_1 = {4a 4f 73 51 68 4d 68 4b 4c 2e 52 75 6e 20 4f 66 79 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}