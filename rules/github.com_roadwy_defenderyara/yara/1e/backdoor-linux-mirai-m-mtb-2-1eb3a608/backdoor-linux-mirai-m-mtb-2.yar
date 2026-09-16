rule Backdoor_Linux_Mirai_M_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 50 50 e2 12 00 00 0a 04 40 95 e5 ?? ff ff eb 00 10 d5 e5 ?? 06 00 eb ?? 31 94 e7 05 00 a0 e1 04 30 8d e5 ?? 01 00 eb 06 00 a0 e1 0d 10 a0 e1 10 20 a0 e3 ?? ?? ?? eb 01 00 70 e3 00 40 a0 e1 [0-09] 06 00 a0 e1 10 d0 8d e2 70 ?? bd e8 } 		$a_03_1 = {8f bc 00 10 24 03 ff ff 8f 99 81 40 10 ?? ?? ?? 02 40 20 21 02 40 10 21 8f bf 00 34 8f b2 00 30 8f b1 00 2c 8f b0 00 28 03 e0 00 08 27 bd 00 38 03 20 f8 09 24 12 ff ff 8f bc 00 10 10 ?? ?? ?? 02 40 10 21 03 ?? ?? ?? 24 12 ff ff 8f bc 00 10 } 		$a_00_2 = {62 6c 61 63 6b 2e 66 72 69 64 67 65 78 70 65 72 74 73 2e 63 63 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1) >=6
 
}