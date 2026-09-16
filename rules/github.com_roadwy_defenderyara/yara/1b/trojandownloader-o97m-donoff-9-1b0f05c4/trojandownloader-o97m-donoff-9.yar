rule TrojanDownloader_O97M_Donoff_9{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 71 61 75 2e 61 6f 69 2e 54 65 78 74 20 26 20 77 70 76 6d 62 69 75 64 68 6d 63 65 75 66 61 62 29 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}