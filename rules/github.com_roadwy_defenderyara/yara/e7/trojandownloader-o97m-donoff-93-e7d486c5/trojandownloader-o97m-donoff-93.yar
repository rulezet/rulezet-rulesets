rule TrojanDownloader_O97M_Donoff_93{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 22 78 65 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 		$a_03_1 = {20 3d 20 22 68 74 74 70 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 		$a_03_2 = {20 3d 20 22 3a 2f 2f 74 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 		$a_03_3 = {20 3d 20 22 68 2e 70 68 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}