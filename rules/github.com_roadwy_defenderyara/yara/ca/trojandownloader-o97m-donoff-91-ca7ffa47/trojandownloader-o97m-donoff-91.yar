rule TrojanDownloader_O97M_Donoff_91{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 28 22 2e 45 22 29 } 		$a_01_1 = {20 3d 20 28 22 78 45 22 29 } 		$a_01_2 = {20 3d 20 54 79 70 65 4e 61 6d 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 64 65 4e 61 6d 65 29 20 3d 20 22 53 74 72 69 6e 67 22 } 		$a_01_3 = {20 3d 20 28 22 2f 43 22 29 } 		$a_01_4 = {20 3d 20 28 22 5e 73 22 29 0d 0a 53 65 6c 65 63 74 20 43 61 73 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}