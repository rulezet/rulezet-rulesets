rule TrojanDownloader_O97M_Donoff_87{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 34 35 2e 31 22 20 2b 20 22 33 35 2f 39 39 39 2e 22 20 2b 20 22 6a 70 22 20 2b 20 22 67 22 } 		$a_01_1 = {22 68 74 74 70 3a 2f 2f 34 22 20 2b 20 22 36 2e 22 20 2b 20 22 33 30 2e 34 35 2e 31 33 35 2f 22 20 2b 20 22 39 39 39 22 20 2b 20 22 2e 22 20 2b 20 22 6a 70 22 20 2b 20 22 67 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}