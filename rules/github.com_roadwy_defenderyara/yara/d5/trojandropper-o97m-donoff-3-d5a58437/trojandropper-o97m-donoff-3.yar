rule TrojanDropper_O97M_Donoff_3{
	meta:
		description = "TrojanDropper:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 34 52 36 52 4f 2f 33 43 73 6d 4d 62 4d 4f 38 59 4e 4c 3a } 		$a_01_1 = {57 4b 49 41 52 62 45 57 53 4b 48 72 41 6a 52 59 } 		$a_01_2 = {56 55 4a 4c 49 41 62 4c 52 4c 41 50 54 44 69 73 } 		$a_01_3 = {56 6c 4d 67 57 32 41 6f 52 43 45 39 39 61 } 		$a_01_4 = {58 64 51 45 55 46 4e 55 6e 46 6e 6e 69 65 32 65 35 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}