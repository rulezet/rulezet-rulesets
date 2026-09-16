rule Trojan_BAT_AgentTesla_AT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 1e 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 13 05 08 11 05 6f ?? ?? ?? 0a 09 18 58 0d 09 07 } 		$a_01_1 = {43 00 43 00 30 00 31 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}