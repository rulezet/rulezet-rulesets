rule Backdoor_Linux_Mirai_AW_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.AW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {78 22 01 00 94 80 00 00 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 0c } 		$a_00_1 = {e5 02 30 43 e2 14 30 0b e5 14 30 1b e5 01 00 53 e3 ef } 		$a_00_2 = {a8 9d e8 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 24 d0 4d e2 24 00 0b e5 28 10 0b e5 30 30 0b e5 2c 20 4b e5 42 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}