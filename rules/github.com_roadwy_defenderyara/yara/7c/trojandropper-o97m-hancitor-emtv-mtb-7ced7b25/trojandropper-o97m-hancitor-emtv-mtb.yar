rule TrojanDropper_O97M_Hancitor_EMTV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 65 64 67 65 2e 64 22 } 		$a_01_1 = {26 20 6a 73 64 20 26 20 22 6c 22 20 26 20 6c 61 7a 20 26 20 68 68 } 		$a_01_2 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 31 29 2e 43 65 6c 6c 28 31 2c 20 31 29 2e 52 61 6e 67 65 2e 54 65 78 74 } 		$a_01_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}