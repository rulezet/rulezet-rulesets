rule TrojanDownloader_O97M_Donoff_FA_vta_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA!vta,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 22 20 26 20 22 6d 79 66 69 6c 65 65 70 65 70 65 2e 65 78 65 } 		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 52 65 70 6c 61 63 65 28 } 		$a_01_2 = {22 2c 20 22 22 29 29 2c 20 53 74 72 50 74 72 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}