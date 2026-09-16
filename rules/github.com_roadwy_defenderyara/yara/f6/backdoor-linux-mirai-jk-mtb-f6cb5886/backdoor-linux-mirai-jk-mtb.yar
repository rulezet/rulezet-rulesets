rule Backdoor_Linux_Mirai_JK_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JK!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 43 0c 8d 4c 18 1c 0f b7 51 10 01 c2 8b 41 08 89 53 0c 8b 51 0c 89 43 04 89 53 08 } 		$a_03_1 = {57 56 53 8b 5c 24 10 8b 43 0c 3b 43 10 7c ?? be dc 00 00 00 8b 13 bf 00 08 00 00 8d 4b 1c 89 f0 e8 fb 03 00 00 83 f8 00 89 c7 7f ?? 7d ?? 83 f8 fe 74 ?? e8 b8 01 00 00 f7 df 89 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}