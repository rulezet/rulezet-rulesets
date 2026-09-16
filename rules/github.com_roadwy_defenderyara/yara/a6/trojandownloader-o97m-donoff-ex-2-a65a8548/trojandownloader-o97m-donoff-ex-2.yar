rule TrojanDownloader_O97M_Donoff_EX_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 5e 2e 65 5e 22 20 2b 20 22 78 5e 65 22 20 2b 20 22 5e 20 20 22 20 26 } 		$a_00_1 = {24 6b 6f 73 3d 27 74 2e 77 65 27 3b 24 72 65 6d 3d 27 65 6e 74 29 2e 64 6f } 		$a_00_2 = {2b 24 6e 69 6d 2b 27 68 74 74 70 73 3a 2f 2f } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}