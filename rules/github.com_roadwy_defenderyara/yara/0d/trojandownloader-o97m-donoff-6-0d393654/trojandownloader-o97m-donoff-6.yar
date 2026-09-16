rule TrojanDownloader_O97M_Donoff_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 7a 7a 76 3a 2f 2f 73 75 78 6b 72 6f 71 6b 79 7a 75 6a 67 65 2e 69 75 73 2f 75 6c 6c 6f 69 6b 2e 6b 64 6b } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}