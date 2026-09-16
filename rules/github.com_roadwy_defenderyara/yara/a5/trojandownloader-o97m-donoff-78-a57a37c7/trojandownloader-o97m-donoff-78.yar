rule TrojanDownloader_O97M_Donoff_78{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } 		$a_00_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 5f } 		$a_00_2 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 22 5c 22 20 26 } 		$a_00_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 } 		$a_00_4 = {30 30 3b 71 75 75 69 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2) >=5
 
}