rule TrojanDropper_O97M_Donoff{
	meta:
		description = "TrojanDropper:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 6f 72 22 20 26 20 22 64 2e 22 20 26 20 22 41 70 70 6c 69 63 61 74 69 6f 22 } 		$a_01_1 = {26 20 22 2e 72 22 20 26 20 22 74 66 22 } 		$a_01_2 = {3d 20 22 54 22 20 26 20 22 45 4d 22 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}