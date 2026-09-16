rule TrojanDownloader_Linux_Bartallex_B{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.B,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 31 2e 32 32 30 2e 31 33 31 2e 37 33 2f 63 61 2f 66 69 6c 65 } 		$a_01_1 = {43 68 72 28 41 73 63 28 22 70 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 69 22 29 29 20 2b 20 22 66 22 20 2b 20 43 68 72 28 33 34 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}