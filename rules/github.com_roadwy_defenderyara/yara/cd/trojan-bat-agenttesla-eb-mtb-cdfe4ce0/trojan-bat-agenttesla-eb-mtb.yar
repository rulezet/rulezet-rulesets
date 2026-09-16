rule Trojan_BAT_AgentTesla_EB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 d1 c4 d1 c2 20 04 00 00 00 63 20 04 00 00 00 62 20 f6 55 15 f3 61 7d ?? ?? ?? ?? 38 38 02 00 00 7e ?? ?? ?? ?? 20 3a c0 42 be 20 98 89 53 36 58 20 49 5c a0 21 59 20 89 ed f5 d2 61 } 	condition:
		((#a_03_0  & 1)*7) >=7
 
}