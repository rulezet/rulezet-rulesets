rule TrojanDownloader_O97M_Donoff_H_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 64 50 69 6e 4f 6b 30 5f 53 50 4c 28 55 73 65 72 46 6f 72 6d 32 2e 53 70 69 6e 42 75 74 74 6f 6e 31 2e } 		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 41 31 2c 20 41 32 2c 20 41 33 29 } 		$a_01_2 = {29 29 20 2f 20 28 31 32 20 2d 20 35 29 29 } 		$a_01_3 = {28 38 38 20 2d 20 35 30 20 2d 20 33 33 29 2c 20 53 74 64 50 69 6e 4f 6b 30 5f 33 5f 31 2c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}