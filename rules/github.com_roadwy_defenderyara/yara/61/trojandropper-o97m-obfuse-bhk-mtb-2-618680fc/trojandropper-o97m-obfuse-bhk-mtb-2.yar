rule TrojanDropper_O97M_Obfuse_BHK_MTB_2{
	meta:
		description = "TrojanDropper:O97M/Obfuse.BHK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 6b 46 66 70 41 71 48 41 2e 62 48 6e 51 67 78 6b } 		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 49 63 62 62 45 7a 74 59 62 2c 20 22 69 75 67 64 79 62 66 73 75 22 2c 20 22 22 29 } 		$a_00_2 = {2e 52 75 6e 20 47 72 61 76 69 74 79 20 26 20 22 22 20 26 20 49 63 62 62 45 7a 74 59 62 2c 20 30 2e 30 30 30 31 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}