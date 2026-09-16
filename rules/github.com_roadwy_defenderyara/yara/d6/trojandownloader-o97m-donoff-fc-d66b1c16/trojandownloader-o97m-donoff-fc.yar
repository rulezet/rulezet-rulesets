rule TrojanDownloader_O97M_Donoff_FC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FC,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 56 47 56 74 63 41 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 20 26 } 		$a_00_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 54 22 20 26 20 22 65 22 20 26 20 22 6d 22 20 26 20 22 70 22 29 20 26 20 22 5c 31 73 2e 62 61 74 22 2c 20 76 62 48 69 64 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}