rule TrojanDownloader_O97M_Donoff_34{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-08] 53 68 65 6c 6c 20 68 6a 36 37 67 62 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}