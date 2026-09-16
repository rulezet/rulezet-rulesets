rule Backdoor_Linux_Mirai_EZ_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.EZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 d0 4d e2 ba 02 00 eb 00 c0 dd e5 0e 00 5c e3 ?? ?? ?? ?? 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3 ab b1 a0 e1 1c cb a0 e1 0d b0 a0 e1 3a cd 8c e2 0c d0 4d e0 00 c0 93 e5 08 30 8d e5 04 c0 8d e5 00 20 8d e5 0c 30 8d e2 00 c0 a0 e3 } 		$a_01_1 = {01 20 52 e2 58 50 9d e5 00 30 a0 03 01 30 a0 13 01 b0 8b e2 05 00 5b e1 00 30 a0 23 01 30 03 32 01 70 d4 e4 00 00 53 e3 01 70 cc e4 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}