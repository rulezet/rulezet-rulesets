rule TrojanDownloader_O97M_Bartallex_3{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 50 6c 4b 74 52 65 62 47 66 20 3d 20 6f 47 64 79 65 4a 64 68 73 64 64 2e 54 65 78 74 42 6f 78 34 20 2b 20 69 75 79 68 67 64 66 73 64 66 20 2b 20 68 79 79 75 65 6a 6b 6a 73 20 2b 20 79 79 65 69 64 73 61 64 66 20 2b 20 79 65 75 69 6a 6a 66 66 73 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}