rule TrojanDownloader_O97M_Donoff_H_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b 71 75 75 69 } 		$a_00_1 = {22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 22 } 		$a_00_2 = {26 20 22 5c 22 20 26 20 22 63 61 6c 63 2e 65 78 65 22 2c } 		$a_00_3 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}