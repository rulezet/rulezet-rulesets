rule TrojanDownloader_O97M_Donoff_67{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 73 75 72 76 69 76 6f 72 73 34 67 2e 6f 72 67 2f 77 22 20 2b 20 22 70 2d 63 6f 22 20 2b 20 22 6e 74 65 6e 74 2f 70 6c 75 67 22 20 2b 20 22 69 6e 73 2f 77 70 2d 64 62 2d 62 61 63 6b 75 70 2d 6d 61 64 65 2f 22 } 		$a_01_1 = {22 63 74 6d 61 79 61 6b 6b 61 62 69 2e 63 6f 6d 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}