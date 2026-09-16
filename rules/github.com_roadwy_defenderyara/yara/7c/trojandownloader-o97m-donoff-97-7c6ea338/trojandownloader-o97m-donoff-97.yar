rule TrojanDownloader_O97M_Donoff_97{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 22 68 64 78 6a 46 73 4c 58 43 6e 74 45 54 79 55 72 56 7a 6d 66 6d 2e 6d 6b 71 6e 6e 77 2f 61 6f 77 74 2f 75 6d 62 61 67 61 2f 75 77 6b 2e 69 62 76 69 6b 62 6d 75 70 6d 75 2f 2f 3a 78 62 62 70 } 		$a_01_1 = {22 71 7a 67 41 63 66 48 45 65 62 55 4a 44 6f 76 4e 79 4f 52 59 4b 55 46 6c 62 76 56 64 4f 4a 4c 6a 48 59 6b 49 62 70 6a 4e 6f 46 73 54 59 61 42 69 71 4d 4f 4c 66 4a 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}