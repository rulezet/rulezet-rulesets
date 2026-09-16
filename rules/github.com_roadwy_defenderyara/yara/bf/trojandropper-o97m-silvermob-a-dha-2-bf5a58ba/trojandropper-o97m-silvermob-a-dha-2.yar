rule TrojanDropper_O97M_SilverMob_A_dha_2{
	meta:
		description = "TrojanDropper:O97M/SilverMob.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 68 72 28 34 36 20 2b 20 28 41 73 63 28 } 		$a_00_1 = {29 20 2d 20 34 36 20 2d 20 32 30 20 2b 20 28 31 32 32 20 2d 20 34 36 29 29 20 4d 6f 64 20 28 31 32 32 20 2d 20 34 36 29 29 } 		$a_00_2 = {2b 20 43 68 72 28 41 73 63 28 4d 69 64 24 28 } 		$a_00_3 = {6f 62 6a 2e 52 75 6e 20 66 69 6c 65 6e 61 6d 65 2c 20 31 2c 20 46 61 6c 73 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}