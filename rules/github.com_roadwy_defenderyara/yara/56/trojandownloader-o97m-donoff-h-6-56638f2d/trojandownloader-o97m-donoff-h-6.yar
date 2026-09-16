rule TrojanDownloader_O97M_Donoff_H_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {2b 20 52 65 70 6c 61 63 65 28 22 73 62 73 74 61 72 74 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29 } 		$a_00_1 = {2c 20 52 65 70 6c 61 63 65 28 22 7a 70 65 6e 22 2c 20 22 7a 22 2c 20 22 4f 22 29 } 		$a_00_2 = {52 65 70 6c 61 63 65 28 22 72 45 4d 50 22 2c 20 22 72 22 2c 20 22 54 22 29 29 } 		$a_00_3 = {3d 20 53 70 6c 69 74 28 75 72 6c 41 72 2c 20 22 20 22 29 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}