rule TrojanDownloader_O97M_Donoff_G_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 48 74 74 22 20 2b 20 22 70 22 20 2b 20 22 2e 22 } 		$a_00_1 = {2c 20 22 6e 22 20 2b 20 22 6b 69 4f 22 20 2b 20 22 61 22 20 2b 20 22 57 73 22 20 2b 20 22 67 22 29 } 		$a_00_2 = {3d 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 65 22 20 2b 20 22 78 65 22 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}