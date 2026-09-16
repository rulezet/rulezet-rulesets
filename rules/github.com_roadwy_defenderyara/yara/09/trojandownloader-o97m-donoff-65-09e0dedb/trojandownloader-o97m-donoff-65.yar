rule TrojanDownloader_O97M_Donoff_65{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 78 65 63 20 3d 20 65 78 65 63 20 2b 20 22 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 4e 6f 6e 69 6e 74 65 72 61 63 74 69 76 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 20 22 20 26 20 73 74 72 } 		$a_00_1 = {53 68 65 6c 6c 20 28 65 78 65 63 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}