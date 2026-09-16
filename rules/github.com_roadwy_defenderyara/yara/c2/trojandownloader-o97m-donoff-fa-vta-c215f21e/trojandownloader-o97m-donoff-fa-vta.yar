rule TrojanDownloader_O97M_Donoff_FA_vta{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FA!vta,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 22 20 26 20 22 78 65 22 29 } 		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 20 30 26 2c 20 52 65 70 6c 61 63 65 28 } 		$a_03_2 = {22 2c 20 22 22 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? [0-20] 2c 20 30 26 2c 20 30 26 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}