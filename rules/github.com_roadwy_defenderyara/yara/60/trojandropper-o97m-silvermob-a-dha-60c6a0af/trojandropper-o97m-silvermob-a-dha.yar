rule TrojanDropper_O97M_SilverMob_A_dha{
	meta:
		description = "TrojanDropper:O97M/SilverMob.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {28 31 29 20 3d 20 22 41 41 42 44 37 37 45 37 45 34 45 37 45 37 45 37 45 33 45 37 45 37 } 		$a_00_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } 		$a_00_2 = {6c 69 76 65 4f 6e } 		$a_00_3 = {73 76 63 68 6f 73 74 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}