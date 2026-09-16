rule TrojanDownloader_O97M_Donoff_102{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 50 52 4b 73 75 56 4f 62 20 26 20 43 68 72 28 46 41 4e 55 6f 38 6e 7a 58 31 6e 69 54 33 56 28 53 33 6d 38 63 76 50 69 6b 72 29 29 } 		$a_01_1 = {46 41 4e 55 6f 38 6e 7a 58 31 6e 69 54 33 56 20 3d 20 53 70 6c 69 74 28 50 52 4b 73 75 56 4f 62 2c 20 22 2c 22 29 } 		$a_01_2 = {47 38 37 76 34 39 49 7a 59 49 54 68 77 7a 28 50 52 4b 73 75 56 4f 62 2c 20 49 6e 38 61 58 64 6a 6d 6b 7a 54 32 4a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}