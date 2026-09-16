rule TrojanDownloader_O97M_Donoff_72{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 22 20 2b 20 66 73 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 2b 20 22 2f 6a 73 2e 6a 73 22 } 		$a_00_1 = {27 74 53 74 72 69 6e 67 73 28 22 22 25 54 45 4d 27 3b } 		$a_00_2 = {2b 3d 20 27 22 22 47 45 54 22 22 2c 22 22 68 74 74 70 3a 2f 27 3b 20 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}