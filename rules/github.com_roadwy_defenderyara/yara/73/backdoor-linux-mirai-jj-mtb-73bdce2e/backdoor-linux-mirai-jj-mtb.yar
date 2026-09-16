rule Backdoor_Linux_Mirai_jj_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.jj!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 c9 66 0f b6 47 09 c1 e9 10 41 8d 0c 08 66 c1 c8 08 0f b7 c0 01 c1 89 d0 81 e2 ff ff 00 00 c1 e8 10 01 d0 41 0f b7 d1 01 d0 41 0f b7 d2 01 d0 8d 04 01 89 c2 c1 ea 10 } 		$a_01_1 = {48 89 c1 40 0f b6 c6 89 c2 c1 e2 08 09 d0 48 98 48 89 c2 48 c1 e2 10 48 09 c2 48 89 d7 48 c1 e7 20 48 09 d7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}