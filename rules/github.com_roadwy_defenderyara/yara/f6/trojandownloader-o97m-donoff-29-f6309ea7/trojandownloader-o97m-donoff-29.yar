rule TrojanDownloader_O97M_Donoff_29{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 61 66 65 74 72 65 65 68 75 6e 74 } 		$a_01_1 = {22 2c 20 22 54 4f 55 43 48 42 22 2c 20 22 6f 6d 22 29 } 		$a_01_2 = {2c 20 22 54 4f 55 43 48 43 22 2c 20 22 2e 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}