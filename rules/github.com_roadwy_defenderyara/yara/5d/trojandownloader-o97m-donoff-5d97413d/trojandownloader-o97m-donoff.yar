rule TrojanDownloader_O97M_Donoff{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 30 2e 32 34 32 2e 31 32 33 2e 31 35 35 2f 22 [0-08] 65 78 65 2f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}