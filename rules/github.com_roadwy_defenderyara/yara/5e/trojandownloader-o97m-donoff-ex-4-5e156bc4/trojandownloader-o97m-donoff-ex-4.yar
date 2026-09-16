rule TrojanDownloader_O97M_Donoff_EX_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EX,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 24 20 [0-10] 2c 20 30 } 		$a_01_1 = {29 2e 72 27 2b 27 65 50 6c 61 27 2b 27 63 65 28 28 5b 43 68 61 52 5d } 		$a_01_2 = {53 79 73 27 2b 27 74 27 2b 27 65 6d 2e 4e 65 74 } 		$a_03_3 = {2f 2c 68 74 74 70 3a 2f [0-04] 2b [0-04] 2f } 		$a_03_4 = {27 2b 27 52 2e 65 78 65 [0-04] 27 2b 27 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}