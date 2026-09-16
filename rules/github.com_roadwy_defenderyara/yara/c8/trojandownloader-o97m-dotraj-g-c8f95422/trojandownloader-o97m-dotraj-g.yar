rule TrojanDownloader_O97M_Dotraj_G{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.G,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 05 a0 0b 61 2d 7a 41 2d 5a 30 2d 39 20 2b 29 2e 52 75 6e [0-01] 28 90 05 01 01 28 22 22 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 20 2b 20 90 1d 15 00 2e 54 65 78 74 42 6f 78 31 29 } 		$a_00_1 = {77 73 63 72 69 70 74 2e 73 68 65 6c 6c } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}