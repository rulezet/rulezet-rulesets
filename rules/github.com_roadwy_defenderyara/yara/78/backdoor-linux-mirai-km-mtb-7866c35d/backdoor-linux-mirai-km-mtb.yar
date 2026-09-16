rule Backdoor_Linux_Mirai_KM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 00 00 02 7c 00 00 26 74 09 10 00 7c 7f 1b 78 41 a2 00 10 48 00 05 a9 93 e3 00 00 3b e0 ff ff } 		$a_01_1 = {80 1f 00 00 7f 84 00 00 40 bc 00 14 80 7f 00 04 4b ff ff c1 90 7f 00 04 48 00 00 14 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}