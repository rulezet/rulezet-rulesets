rule TrojanDownloader_O97M_Donoff_G_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2b 20 22 6c 22 20 2b 20 22 6c } 		$a_00_1 = {64 69 73 6b 64 66 72 67 } 		$a_00_2 = {47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 26 20 22 5c 22 20 2b 20 22 5c 22 } 		$a_00_3 = {4f 62 61 6d 61 20 4e 75 6b } 		$a_00_4 = {3d 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 65 78 65 22 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}