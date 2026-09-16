rule TrojanDownloader_O97M_Donoff_41{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 		$a_00_1 = {73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } 		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 2e 54 65 78 74 42 6f 78 [0-04] 20 2b } 	condition:
		((#a_01_0  & 1)*-1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}