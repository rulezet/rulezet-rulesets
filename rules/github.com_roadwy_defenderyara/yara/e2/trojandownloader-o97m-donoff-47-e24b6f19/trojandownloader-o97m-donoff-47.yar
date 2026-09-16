rule TrojanDownloader_O97M_Donoff_47{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 20 22 20 26 20 } 		$a_01_1 = {65 76 2d 2d 21 2d 61 6c } 		$a_01_2 = {57 73 2d 2d 21 2d 63 72 2d 2d 21 2d 69 70 2d 2d 21 2d 74 } 		$a_01_3 = {26 20 22 2e 22 20 26 20 22 6a 22 20 26 20 22 73 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}