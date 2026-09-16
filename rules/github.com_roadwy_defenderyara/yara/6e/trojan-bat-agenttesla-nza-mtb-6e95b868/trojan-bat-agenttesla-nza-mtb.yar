rule Trojan_BAT_AgentTesla_NZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 bb 0f 00 00 95 7e ?? ?? ?? 04 19 9a 20 28 0f 00 00 95 11 04 61 7e 1d 00 00 04 19 9a 20 ce 0d 00 00 95 59 7e 1d 00 00 04 1a 9a 19 95 61 7e 1d 00 00 04 19 9a 20 7d 04 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}