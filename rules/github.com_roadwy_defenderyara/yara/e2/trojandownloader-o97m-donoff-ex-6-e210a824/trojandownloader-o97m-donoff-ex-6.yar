rule TrojanDownloader_O97M_Donoff_EX_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 56 47 56 74 63 41 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 26 } 		$a_00_1 = {53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 58 44 59 75 63 47 6c 6d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 2c 20 76 62 48 69 64 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}