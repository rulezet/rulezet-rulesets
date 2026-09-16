rule TrojanDownloader_O97M_Donoff_32{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 77 78 65 65 69 68 7a 70 79 70 7a 64 6f 38 2e 73 3a 2f 72 77 6d 74 2f 74 65 31 67 3d 68 6f 6c 63 33 62 6f 6c 6b 73 2f 77 2f 3f 6e 67 78 78 6f 64 64 63 2e 77 78 31 2f 2e 22 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}