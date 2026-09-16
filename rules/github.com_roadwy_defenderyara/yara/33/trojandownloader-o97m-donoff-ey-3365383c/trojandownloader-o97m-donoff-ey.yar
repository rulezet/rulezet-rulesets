rule TrojanDownloader_O97M_Donoff_EY{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 72 73 22 } 		$a_00_1 = {3d 20 70 6f 36 48 20 2b 20 22 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 65 } 		$a_00_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 70 6f 36 48 2c 20 76 62 48 69 64 65 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}