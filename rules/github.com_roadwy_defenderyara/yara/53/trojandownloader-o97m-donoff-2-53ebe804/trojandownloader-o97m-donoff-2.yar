rule TrojanDownloader_O97M_Donoff_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 34 33 2e 31 34 36 2f 39 30 39 2e 6a 70 67 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}