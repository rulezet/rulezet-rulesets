rule TrojanDownloader_O97M_Donoff_68{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 25 5c 22 20 2b 20 66 69 6c 65 6e 61 6d 65 31 20 2b 20 22 2e 65 22 20 2b 20 22 78 22 20 2b 20 22 45 27 27 3b 7d 22 } 		$a_01_1 = {3d 20 22 20 22 22 27 50 6f 77 5e 65 72 5e 53 68 5e 65 6c 6c } 		$a_01_2 = {68 74 22 20 2b 20 22 74 70 22 20 2b 20 22 3a 2f 22 20 2b 20 22 2f 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}