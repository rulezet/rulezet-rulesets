rule TrojanDownloader_O97M_Donoff_EU{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EU,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2c 20 22 57 53 63 72 69 70 74 22 20 26 } 		$a_00_1 = {23 22 0d 0a 20 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e } 		$a_02_2 = {43 61 6c 6c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 29 2e 52 75 6e 28 4d 6f 64 75 6c 65 31 2e [0-16] 28 [0-16] 2c 20 4c 54 72 69 6d 28 [0-16] 29 2c 20 22 22 2c } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}