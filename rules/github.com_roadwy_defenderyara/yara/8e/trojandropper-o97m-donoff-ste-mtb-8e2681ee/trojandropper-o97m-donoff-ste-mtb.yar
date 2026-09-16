rule TrojanDropper_O97M_Donoff_STE_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.STE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 64 6f 63 75 6d 65 6e 74 73 2e 70 72 6f 2e 62 72 2f 22 } 		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 29 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 2e 43 72 65 61 74 65 20 4d 69 63 72 6f 73 6f 66 74 43 44 54 32 30 32 32 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 69 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}