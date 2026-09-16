rule TrojanDownloader_Linux_Bartallex_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 69 76 65 73 65 63 6f 6e 64 63 68 61 6e 63 65 2e 70 72 65 73 73 2f 73 79 73 2f 63 31 36 30 38 65 63 38 37 35 32 37 33 64 36 30 33 34 36 64 64 37 37 36 30 32 65 35 30 64 33 30 32 33 65 39 61 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}