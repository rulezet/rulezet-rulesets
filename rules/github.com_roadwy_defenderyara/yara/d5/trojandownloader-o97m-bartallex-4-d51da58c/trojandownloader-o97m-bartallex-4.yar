rule TrojanDownloader_O97M_Bartallex_4{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 47 39 33 5a 58 4a 54 61 47 56 73 62 43 41 74 52 58 68 6c 59 33 56 30 61 57 39 75 55 47 39 73 61 57 4e 35 49 47 4a 35 63 47 46 7a 63 79 41 74 62 6d 39 77 63 6d 39 6d 61 57 78 6c 49 43 31 33 61 57 35 6b 62 33 64 7a 64 48 6c 73 5a 53 42 6f 61 57 52 6b 5a 57 34 67 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}