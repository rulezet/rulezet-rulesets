rule TrojanDownloader_O97M_Donoff_139{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 28 32 34 37 2c 20 22 69 20 70 2e 67 61 2f 6e 63 2f 6f 75 74 63 74 2f 74 27 6e 74 61 6e 44 74 69 62 2e 4e 63 62 77 28 59 69 50 65 7c 27 61 6f 6c 6f 67 68 65 72 71 61 73 68 2f 70 68 67 72 64 6c 6f 29 65 43 57 65 74 6a 2d 6e 4a 72 69 78 20 29 73 6e 6f 77 65 61 78 67 2e 6d 2d 69 65 3a 74 28 69 53 6f 77 2e 6e 6c 65 74 20 65 6f 65 42 68 49 73 } 		$a_01_1 = {65 28 31 31 39 2c 20 22 6f 70 63 52 52 73 2e 64 65 2e 2f 6d 74 77 6d 6d 2f 69 4d 63 3a 6d 2e 6f 31 6d 69 74 77 69 2f 76 74 72 5a 2f 61 63 69 2f 65 55 70 77 6e 67 32 79 50 68 2f 78 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}