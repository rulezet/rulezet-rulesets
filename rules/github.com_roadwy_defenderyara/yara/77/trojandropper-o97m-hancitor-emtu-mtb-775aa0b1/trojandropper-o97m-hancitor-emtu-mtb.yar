rule TrojanDropper_O97M_Hancitor_EMTU_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 65 64 67 65 2e 64 22 } 		$a_01_1 = {44 69 6d 20 6a 73 64 20 41 73 20 53 74 72 69 6e 67 } 		$a_01_2 = {44 69 6d 20 70 75 73 20 41 73 20 53 74 72 69 6e 67 } 		$a_03_3 = {2e 52 75 6e 20 66 61 20 26 20 22 20 22 20 26 20 79 79 2c 20 77 69 6e 64 6f 77 53 74 79 6c 65 2c 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 90 0c 02 00 45 6e 64 20 49 66 90 0c 02 00 45 6e 64 20 53 75 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}