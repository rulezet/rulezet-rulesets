rule TrojanDownloader_O97M_Donoff_60{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 57 69 6e 33 32 3b 20 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 29 27 29 3b 22 } 		$a_01_1 = {2e 65 5e 78 65 27 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}