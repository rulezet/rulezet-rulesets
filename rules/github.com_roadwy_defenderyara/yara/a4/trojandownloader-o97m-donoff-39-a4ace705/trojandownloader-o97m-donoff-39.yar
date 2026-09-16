rule TrojanDownloader_O97M_Donoff_39{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 5e 2e 65 5e 22 20 2b 20 22 78 5e 65 22 } 		$a_01_1 = {49 22 20 2b 20 22 6e 76 22 20 2b 20 22 6f 6b 65 2d 45 22 } 		$a_01_2 = {2b 20 22 65 20 20 20 22 20 2b 20 22 2f 63 20 22 22 22 20 2b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}