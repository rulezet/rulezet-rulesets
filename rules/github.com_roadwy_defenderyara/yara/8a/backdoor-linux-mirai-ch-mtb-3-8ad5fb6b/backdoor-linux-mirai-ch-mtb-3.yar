rule Backdoor_Linux_Mirai_Ch_MTB_3{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {1c 55 9f e5 b4 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 1d ff ff 1a 00 34 95 e5 04 00 53 e3 1a ff ff 1a 02 0b 85 e2 08 00 80 e2 ?? ?? 00 eb 00 40 a0 e1 03 0b 85 e2 0c 00 80 e2 ?? ?? 00 eb 00 20 a0 e1 01 0b 85 e2 04 00 80 e2 04 10 a0 e1 ?? ?? 00 eb 0d ff ff ea } 		$a_03_1 = {04 e0 2d e5 24 c0 9f e5 00 30 a0 e1 0c d0 4d e2 00 10 93 e5 04 20 80 e2 00 c0 8d e5 10 00 9f e5 00 c0 a0 e3 0c 30 9f e5 04 c0 8d e5 ?? ?? 00 eb } 		$a_03_2 = {ec 57 9f e5 40 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 02 00 00 1a 00 34 95 e5 04 00 53 e3 fc 00 00 0a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}