rule TrojanDownloader_O97M_Donoff_10{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 61 64 73 2d 6c 65 74 74 65 72 2e 69 6e 66 6f 2f 63 6c 69 65 6e 74 5f 73 63 72 69 70 74 2e 6a 73 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}