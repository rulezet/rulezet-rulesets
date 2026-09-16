rule TrojanDownloader_Linux_Bartallex_A_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 33 35 2f 75 70 64 2f 69 6e 73 74 61 6c 6c } 		$a_01_1 = {3a 2f 2f 31 34 36 2e 31 38 35 2e 32 31 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}