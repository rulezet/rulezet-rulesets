rule TrojanDropper_O97M_Donoff_4{
	meta:
		description = "TrojanDropper:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2c 20 2c 20 43 42 79 74 65 28 22 26 22 20 2b 20 43 68 72 28 90 10 03 00 20 2d 20 90 10 03 00 29 20 26 } 		$a_02_1 = {53 74 72 52 65 76 65 72 73 65 28 22 61 70 78 45 22 29 20 2b 20 4d 69 64 28 22 [0-10] 6e 64 45 6e 76 69 72 [0-10] 22 2c 20 90 10 02 00 2c 20 37 29 20 2b 20 22 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}