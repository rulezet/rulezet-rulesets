rule TrojanDownloader_O97M_Donoff_14{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {62 65 65 73 74 65 72 69 70 68 75 64 69 6c 75 6c 75 6e 70 65 63 68 61 72 61 6b 6b 65 65 73 5c 70 6d 2e 6a 5c 5c 3a 73 70 74 74 68 } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}