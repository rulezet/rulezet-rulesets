rule TrojanDownloader_O97M_Donoff_11{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 77 6d 31 71 50 35 58 33 34 65 71 2e 4f 70 65 6e 20 22 70 6f 53 54 22 2c 20 62 74 39 74 7a 44 2e 4a 33 6a 45 65 74 31 55 35 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}