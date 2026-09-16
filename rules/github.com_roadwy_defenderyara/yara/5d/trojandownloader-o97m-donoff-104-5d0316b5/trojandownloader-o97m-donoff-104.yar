rule TrojanDownloader_O97M_Donoff_104{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 77 77 77 2e 67 75 72 6d 65 74 61 72 69 66 6c 65 72 2e 63 6f 6d 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 79 65 6d 65 6b 2d 74 61 72 69 66 6c 65 72 69 2f 22 } 		$a_01_1 = {22 77 77 77 2e 67 6f 72 67 65 2d 70 72 6f 66 6f 6e 64 65 2e 78 22 20 2b 20 22 78 78 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 35 2f 30 36 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}