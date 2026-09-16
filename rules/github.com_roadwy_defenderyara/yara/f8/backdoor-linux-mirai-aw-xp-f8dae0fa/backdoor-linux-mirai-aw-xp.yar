rule Backdoor_Linux_Mirai_AW_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AW!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {e5 00 20 93 e5 00 c0 92 e5 04 30 dc e5 07 00 53 e1 05 00 a0 11 04 } 		$a_00_1 = {00 ea 00 c1 92 e7 04 30 dc e5 07 00 53 e1 04 00 00 0a 01 00 80 e2 01 00 50 e1 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}