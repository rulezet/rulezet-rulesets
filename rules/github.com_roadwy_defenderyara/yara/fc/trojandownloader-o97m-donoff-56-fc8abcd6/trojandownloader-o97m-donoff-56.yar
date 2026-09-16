rule TrojanDownloader_O97M_Donoff_56{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 64 2f 2e 2d 74 68 6d 70 61 55 38 78 72 6d 61 6e 65 69 2f 74 68 44 68 65 6f 6f 73 77 6d 64 2f 74 4a 4a 64 2e 77 63 75 6f 6f 65 3a 68 61 68 62 } 		$a_01_1 = {6f 78 52 58 79 42 68 43 59 79 67 30 20 3d } 		$a_01_2 = {2e 6f 78 52 58 79 42 68 43 59 79 67 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}