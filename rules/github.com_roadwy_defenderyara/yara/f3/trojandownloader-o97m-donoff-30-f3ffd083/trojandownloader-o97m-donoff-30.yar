rule TrojanDownloader_O97M_Donoff_30{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 		$a_01_1 = {53 68 65 6c 6c } 		$a_01_2 = {2e 65 78 65 22 2c } 		$a_01_3 = {62 6f 6f 6b 6d 79 72 6f 6f 6d 2e 70 6b } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}