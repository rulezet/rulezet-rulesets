rule TrojanDownloader_O97M_Donoff_44{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 70 2f 22 20 2b 20 22 72 65 61 64 } 		$a_00_1 = {20 2b 20 22 2e 65 58 45 } 		$a_01_2 = {20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 62 6c 65 53 74 79 6c 65 20 3d 20 22 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}