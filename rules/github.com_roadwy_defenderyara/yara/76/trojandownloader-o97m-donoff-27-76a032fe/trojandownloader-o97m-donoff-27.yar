rule TrojanDownloader_O97M_Donoff_27{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 22 68 74 74 70 3a 2f 2f 65 72 6c 73 68 61 72 64 77 61 72 65 63 6f 2e 63 6f 6d 2f 90 12 01 00 2f 90 1d 05 00 2e 65 78 65 22 22 3e 3e 90 1d 05 00 2e 56 42 53 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}