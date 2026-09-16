rule TrojanDownloader_O97M_Donoff_33{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 52 75 6e 20 4a 6f 69 6e 28 [0-10] 2c 20 [0-10] 29 2c 20 [0-08] 0d 0a } 		$a_03_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}