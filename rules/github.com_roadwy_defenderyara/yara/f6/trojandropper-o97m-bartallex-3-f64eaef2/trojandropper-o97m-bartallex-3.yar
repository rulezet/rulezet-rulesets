rule TrojanDropper_O97M_Bartallex_3{
	meta:
		description = "TrojanDropper:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 63 61 73 65 28 22 77 69 4e 33 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 64 6f 72 50 5f 32 22 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 20 74 63 75 22 29 } 		$a_01_1 = {69 76 6f 72 79 20 26 20 22 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}