rule TrojanDownloader_O97M_Donoff_BM{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BM,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {28 29 20 41 73 20 4f 62 6a 65 63 74 0d 0a 44 69 } 		$a_00_1 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 0d 0a } 		$a_00_2 = {3d 20 22 22 20 26 20 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}