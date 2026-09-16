rule TrojanDownloader_O97M_Donoff_53{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 20 22 6e 65 70 4f 22 2c 20 90 0f 02 00 29 2c 20 90 10 02 00 2c 20 73 28 90 10 04 00 2c 20 22 54 45 47 22 2c 20 90 10 04 00 29 2c 20 73 28 90 10 04 00 2c 20 22 } 		$a_03_1 = {22 64 6e 65 53 22 2c 20 90 0f 02 00 29 2c 20 90 10 02 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}