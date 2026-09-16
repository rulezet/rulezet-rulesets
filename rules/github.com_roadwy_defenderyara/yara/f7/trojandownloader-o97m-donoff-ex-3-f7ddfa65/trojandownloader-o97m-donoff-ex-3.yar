rule TrojanDownloader_O97M_Donoff_EX_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {22 70 6f 77 65 22 } 		$a_00_1 = {22 74 2e 57 65 62 22 } 		$a_03_2 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-10] 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 } 		$a_00_3 = {28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}