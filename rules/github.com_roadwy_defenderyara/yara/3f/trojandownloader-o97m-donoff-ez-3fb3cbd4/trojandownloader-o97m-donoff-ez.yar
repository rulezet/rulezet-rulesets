rule TrojanDownloader_O97M_Donoff_EZ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EZ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2b 20 22 63 22 20 2b 20 22 6d 64 20 2f 56 22 20 2b 20 22 20 2f 43 20 22 20 2b 20 43 68 72 28 33 34 29 20 2b } 		$a_00_1 = {3d 20 4d 69 64 28 } 		$a_00_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}