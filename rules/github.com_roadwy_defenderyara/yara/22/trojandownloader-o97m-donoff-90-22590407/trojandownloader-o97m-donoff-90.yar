rule TrojanDownloader_O97M_Donoff_90{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } 		$a_02_1 = {20 41 73 20 53 74 72 69 6e 67 29 [0-10] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e [0-10] 2c 20 30 [0-10] 45 6e 64 20 53 75 62 } 		$a_02_2 = {26 20 63 68 72 77 28 [0-20] 29 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}