rule Backdoor_Linux_Mirai_BJ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 04 85 20 e1 50 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 20 e1 50 00 } 		$a_00_1 = {8b 0d 39 d9 10 00 8b 55 f0 8b 45 f4 89 c3 29 d3 89 da 89 c8 89 14 85 20 e1 50 00 89 c8 8b 04 85 20 e1 50 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}