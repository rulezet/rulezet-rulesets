rule Backdoor_Linux_Mirai_Ch_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.Ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 a0 e3 98 38 8d e5 04 30 83 e2 00 20 a0 e3 ?? 20 83 e7 04 30 83 e2 80 00 53 e3 fa ff ff 1a 18 28 8d e5 7c 30 43 e2 00 50 a0 e3 ?? 50 83 e7 04 30 83 e2 80 00 53 e3 ?? ff ff ?? a6 32 a0 e1 03 91 a0 } 		$a_03_1 = {30 d6 e5 b0 30 c3 e3 ?? 30 83 e3 00 30 c6 e5 00 10 d6 e5 01 30 a0 e3 09 30 c6 e5 0a 10 c1 e3 ?? 30 83 e2 05 10 81 } 		$a_00_2 = {eb ff 10 00 e2 20 34 a0 e1 20 28 a0 e1 00 00 51 e3 ?? 00 51 13 ff c0 03 e2 ff 20 02 e2 20 ec a0 e1 f5 ff ff 0a 03 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}