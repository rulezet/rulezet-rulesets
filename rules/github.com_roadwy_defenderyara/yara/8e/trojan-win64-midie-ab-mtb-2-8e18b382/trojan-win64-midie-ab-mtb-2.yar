rule Trojan_Win64_Midie_AB_MTB_2{
	meta:
		description = "Trojan:Win64/Midie.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f b7 4c 24 38 c1 e1 ?? 48 63 c9 8b 04 08 89 44 24 2c b8 ?? 00 00 00 } 		$a_01_1 = {48 8b 4c 24 30 48 03 c8 48 8b c1 8b 4c 24 28 d1 e1 8b c9 0f b7 04 08 } 	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}