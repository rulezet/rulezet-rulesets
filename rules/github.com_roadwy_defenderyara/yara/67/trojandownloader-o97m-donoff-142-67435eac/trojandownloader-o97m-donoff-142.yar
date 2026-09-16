rule TrojanDownloader_O97M_Donoff_142{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 58 2f 4f 74 4e 65 79 70 2e 4a 2f 49 61 65 4e 53 69 29 29 3a 2e 64 6c 28 20 72 74 70 70 6d 2f 69 3b 74 63 6e 6d 74 65 6d 46 29 63 53 65 74 74 74 6f 70 70 65 57 69 24 68 73 63 6d 6d 6a 20 6c 28 27 79 2e 65 74 62 6d 43 63 28 53 79 54 24 4f 6f 62 65 65 5b 61 74 20 2d 63 65 78 6c 3d 64 65 2c 77 2d 57 45 69 70 6c 47 27 65 20 2e 2e 46 6d 6c 3a 65 4e 74 74 29 64 74 61 3a 63 28 63 65 6c 61 24 79 5d 69 3b 65 4e 6c 6f 47 61 68 66 29 6a 2e 65 6c 71 6b 74 66 28 62 6d 68 6e 78 65 61 6f 65 4f 65 53 77 69 65 50 2f 6d 2d 74 2e 6f 55 64 2e 61 61 77 73 74 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}