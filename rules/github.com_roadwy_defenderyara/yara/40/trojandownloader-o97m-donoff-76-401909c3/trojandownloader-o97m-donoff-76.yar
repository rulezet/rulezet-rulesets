rule TrojanDownloader_O97M_Donoff_76{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 6f 72 72 79 2c 20 77 65 20 72 61 6e 20 69 6e 74 6f 20 61 20 70 72 6f 62 6c 65 6d } 		$a_00_1 = {47 6f 20 6f 6e 6c 69 6e 65 20 74 6f 20 6c 6f 6f 6b 20 66 6f 72 20 61 64 64 69 74 69 6f 6e 61 6c 20 68 65 6c 70 } 		$a_02_2 = {3d 20 53 68 65 6c 6c 28 [0-08] 28 [0-08] 29 2c [0-10] 29 [0-02] 44 69 6d } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}