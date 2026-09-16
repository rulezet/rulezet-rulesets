rule Trojan_BAT_AgentTesla_EAH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 11 08 11 04 07 11 04 9a 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 2a 11 2a 3a } 		$a_01_1 = {16 13 05 11 05 16 fe 01 13 12 11 12 2c 05 17 13 05 2b 12 16 25 13 05 13 13 11 13 2c 05 17 13 05 2b 03 17 13 05 17 13 06 11 06 16 fe 01 13 14 11 14 2c 05 17 13 06 2b 12 } 		$a_01_2 = {52 65 70 6c 61 63 65 } 		$a_01_3 = {53 70 6c 69 74 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}