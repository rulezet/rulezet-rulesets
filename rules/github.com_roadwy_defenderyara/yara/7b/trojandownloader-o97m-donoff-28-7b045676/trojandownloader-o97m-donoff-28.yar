rule TrojanDownloader_O97M_Donoff_28{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 [0-10] 28 29 [0-10] 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 69 73 74 31 2e 54 61 67 [0-08] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}