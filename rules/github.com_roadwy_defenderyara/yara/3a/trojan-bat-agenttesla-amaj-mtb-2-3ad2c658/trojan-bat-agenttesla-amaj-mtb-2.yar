rule Trojan_BAT_AgentTesla_AMAJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 03 17 8d ?? 00 00 01 25 16 09 20 ?? ?? 00 00 d6 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 d0 } 		$a_03_1 = {03 08 04 08 1f 09 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 31 dd } 		$a_80_2 = {4c 6a 72 6f 72 61 72 6a 64 72 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}