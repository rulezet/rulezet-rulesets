rule TrojanDownloader_O97M_Donoff_FD_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 20 2b } 		$a_01_1 = {56 42 41 2e 53 68 65 6c 6c 24 20 22 22 20 2b 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}