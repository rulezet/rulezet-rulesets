rule TrojanDownloader_O97M_Donoff_13{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 41 5e 44 22 20 2b 20 } 		$a_01_1 = {27 25 41 70 22 20 2b 20 } 		$a_01_2 = {20 3d 20 22 58 45 20 } 		$a_01_3 = {74 74 70 3a 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}