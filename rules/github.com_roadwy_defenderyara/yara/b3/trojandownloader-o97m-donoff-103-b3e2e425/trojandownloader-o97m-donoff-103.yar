rule TrojanDownloader_O97M_Donoff_103{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 61 6e 6d 6f 74 6f 72 70 65 6e 69 6e 73 75 6c 61 72 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 6c 6f 67 6f 2e 67 69 66 22 } 		$a_01_1 = {22 65 78 65 2e 64 72 6f 57 5f 74 66 6f 73 6f 72 63 69 4d 22 29 2c } 		$a_01_2 = {44 42 6f 4d 6a 44 28 62 5a 55 4b 58 46 64 6b 42 57 6a } 		$a_01_3 = {78 6e 63 4c 43 4b 4e 4a 41 77 50 61 2c 20 62 5a 55 4b 58 46 64 6b 42 57 6a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}