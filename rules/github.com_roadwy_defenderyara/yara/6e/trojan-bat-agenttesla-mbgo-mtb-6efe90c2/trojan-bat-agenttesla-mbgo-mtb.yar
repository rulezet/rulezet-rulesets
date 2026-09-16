rule Trojan_BAT_AgentTesla_MBGO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 7e 01 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 7e 02 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 14 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}