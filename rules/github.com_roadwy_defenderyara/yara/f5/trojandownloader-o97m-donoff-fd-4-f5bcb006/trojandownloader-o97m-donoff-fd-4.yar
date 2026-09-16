rule TrojanDownloader_O97M_Donoff_FD_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FD,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } 		$a_01_1 = {2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 } 		$a_01_2 = {20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 20 2b } 		$a_01_3 = {56 42 41 2e 53 68 65 6c 6c 24 20 22 22 20 2b 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}