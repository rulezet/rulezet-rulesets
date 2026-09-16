rule TrojanDropper_O97M_Obfuse_BK_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 61 33 66 52 34 74 20 26 20 22 20 22 20 26 20 61 76 63 36 53 67 } 		$a_01_1 = {3d 20 53 70 6c 69 74 28 61 73 75 4d 57 52 2c 20 43 68 72 28 31 31 20 2b 20 31 31 20 2b 20 31 31 20 2b 20 31 31 29 29 } 		$a_01_2 = {3d 20 61 4b 66 59 44 51 28 61 50 35 65 57 28 61 79 33 35 6f 28 61 6c 48 56 30 37 29 2c 20 31 35 29 29 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}