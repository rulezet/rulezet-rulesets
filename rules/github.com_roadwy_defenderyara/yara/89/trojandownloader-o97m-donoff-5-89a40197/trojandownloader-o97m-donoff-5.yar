rule TrojanDownloader_O97M_Donoff_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 68 65 77 65 6c 6c 74 61 6b 65 62 65 72 6c 69 6e 2e 63 6f 6d 2f 39 32 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}