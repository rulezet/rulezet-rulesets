rule TrojanDownloader_O97M_Bartallex_7{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 20 22 70 6f 77 65 72 22 20 26 20 22 73 68 65 6c 6c 22 20 26 20 22 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 6e 6f 65 78 69 74 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}