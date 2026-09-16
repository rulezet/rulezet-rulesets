rule Trojan_BAT_AgentTesla_NEC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 28 ?? ?? ?? 0a 20 ?? ?? ?? 00 da 13 05 11 05 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 06 07 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b3 } 		$a_01_1 = {f4 02 0f 03 ef 02 df 02 df 02 eb 02 df 02 df 02 df 02 df 02 e3 02 df 02 df 02 df 02 df 02 cd 02 cd 02 d6 02 df 02 df 02 ea 02 05 03 df 02 df 02 df } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}