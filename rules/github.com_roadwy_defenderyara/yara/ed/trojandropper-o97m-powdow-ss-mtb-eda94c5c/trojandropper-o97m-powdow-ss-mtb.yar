rule TrojanDropper_O97M_Powdow_SS_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 6c 6f 6b 6b 6f 6f 6b 61 2e 63 6f 70 79 66 69 6c 65 20 4f 69 77 61 2c 20 45 6e 76 69 72 6f 6e 24 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 6b 22 20 2b 20 22 6f 6f 2e 63 6f 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 6d 22 29 2c 20 54 72 75 65 [0-03] 45 6e 64 20 53 75 62 } 		$a_01_1 = {4c 6f 6b 6b 6f 75 6d 6d 7a 64 64 64 20 3d 20 4a 6f 69 6e 28 50 6f 6f 61 72 6f 6b 73 6b 7a 61 73 64 2c 20 22 22 29 } 		$a_01_2 = {53 68 65 6c 6c 20 28 6c 61 6b 61 6b 61 6b 61 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}