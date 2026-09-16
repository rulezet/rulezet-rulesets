rule TrojanDownloader_O97M_Donoff_31{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 75 2f 76 36 3f 3a 74 77 77 73 6f 78 65 78 70 7a 72 31 64 2f 6c 68 35 67 31 2e 64 65 6d 70 2f 7a 73 70 31 65 2e 64 2f 6f 69 37 64 2e 65 63 31 66 61 74 71 2f 62 3d 6f 77 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}