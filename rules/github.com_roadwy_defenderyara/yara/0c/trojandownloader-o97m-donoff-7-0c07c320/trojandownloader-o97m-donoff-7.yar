rule TrojanDownloader_O97M_Donoff_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 34 36 2e 33 30 2e 34 31 22 20 2b 20 22 2e 31 35 30 2f 22 20 2b 20 22 62 62 2e 74 79 22 20 2b 20 22 70 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}