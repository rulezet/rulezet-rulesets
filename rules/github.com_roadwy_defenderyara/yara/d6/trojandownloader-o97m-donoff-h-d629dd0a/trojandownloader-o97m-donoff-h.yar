rule TrojanDownloader_O97M_Donoff_H{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 65 20 36 35 20 54 6f 20 39 30 } 		$a_01_1 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 36 35 29 20 26 20 } 		$a_01_2 = {43 61 73 65 20 39 37 20 54 6f 20 31 32 32 } 		$a_01_3 = {29 20 4d 6f 64 20 32 36 29 20 2b 20 39 37 29 20 26 20 } 		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}