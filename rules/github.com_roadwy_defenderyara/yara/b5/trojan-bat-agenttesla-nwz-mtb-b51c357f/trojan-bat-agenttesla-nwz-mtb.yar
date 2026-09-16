rule Trojan_BAT_AgentTesla_NWZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 a8 01 00 00 95 9e 7e ?? ?? ?? 04 7e 1e 00 00 04 18 9a 20 c5 04 00 00 95 61 80 23 00 00 04 2b 52 7e 23 00 00 04 7e 1e 00 00 04 18 9a 20 5f 04 00 00 95 33 3e 7e 06 00 00 04 16 9a 19 9a 7e 27 00 00 04 25 17 58 80 27 00 00 04 e0 7e 1e 00 00 04 18 9a 20 37 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}