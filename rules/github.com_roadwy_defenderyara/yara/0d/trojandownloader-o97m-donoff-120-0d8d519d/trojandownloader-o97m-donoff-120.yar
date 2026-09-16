rule TrojanDownloader_O97M_Donoff_120{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 20 28 4e 65 77 2d 4f 62 6a 65 63 74 } 		$a_03_1 = {27 25 54 45 4d 50 25 5c ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 27 29 3b 53 74 61 [0-01] 72 74 20 28 25 54 45 4d 50 25 5c 90 1b 00 2e 65 78 65 29 22 29 } 		$a_01_2 = {50 6f 5e 77 65 72 53 5e 68 5e 65 6c 6c 20 2d 45 78 5e 65 5e 63 75 74 69 6f 5e 6e 50 6f 6c 5e 69 63 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}