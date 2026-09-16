rule TrojanDownloader_O97M_Donoff_EX{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 5e 78 65 5e 20 20 22 } 		$a_00_1 = {2e 65 78 22 20 2b 20 22 65 } 		$a_00_2 = {28 24 75 6d 2e 54 6f 53 74 72 69 6e 67 28 29 2c 20 24 70 70 29 3b } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}