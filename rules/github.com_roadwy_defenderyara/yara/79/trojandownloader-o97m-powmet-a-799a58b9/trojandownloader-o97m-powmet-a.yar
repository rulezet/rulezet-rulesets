rule TrojanDownloader_O97M_Powmet_A{
	meta:
		description = "TrojanDownloader:O97M/Powmet.A,SIGNATURE_TYPE_MACROHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } 		$a_00_1 = {53 68 65 6c 6c 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 20 26 } 		$a_00_2 = {22 2d 77 69 6e 64 6f 77 20 68 69 64 64 65 6e 20 2d 65 20 } 		$a_00_3 = {63 41 42 76 41 48 63 41 5a 51 42 79 41 48 4d 41 61 41 42 6c 41 47 77 41 62 41 41 75 41 47 55 41 65 41 42 6c 41 43 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=31
 
}