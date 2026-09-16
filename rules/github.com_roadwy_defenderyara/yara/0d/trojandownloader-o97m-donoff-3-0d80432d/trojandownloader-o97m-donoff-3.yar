rule TrojanDownloader_O97M_Donoff_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 70 6c 69 74 28 22 [0-30] 33 34 66 34 33 2b 62 75 68 75 35 2e 72 75 2f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}