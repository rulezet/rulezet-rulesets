rule TrojanDownloader_O97M_Donoff_EY_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EY,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 22 20 2b 20 22 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 45 78 22 20 2b 20 22 65 63 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 22 20 2b 20 22 61 6e 64 20 28 4e 65 77 2d 4f 62 6a 65 22 20 2b 20 22 63 74 20 53 79 73 74 22 20 2b 20 22 65 6d 2e 4e 65 74 2e 57 65 62 43 22 20 2b 20 22 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 22 20 2b 20 22 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f } 	condition:
		((#a_00_0  & 1)*1) >=1
 
}