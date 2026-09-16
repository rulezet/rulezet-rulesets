rule TrojanDropper_O97M_Donoff_2{
	meta:
		description = "TrojanDropper:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 41 72 72 61 79 28 22 43 4d 22 2c 20 22 44 2e 22 2c 20 22 45 78 22 2c 20 22 65 20 22 2c 20 22 2f 63 22 2c 20 22 20 22 22 22 2c 20 22 70 4f 22 2c 20 22 77 } 		$a_01_1 = {22 72 65 22 2c 20 22 61 64 22 2c 20 22 2e 70 22 2c 20 22 68 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}