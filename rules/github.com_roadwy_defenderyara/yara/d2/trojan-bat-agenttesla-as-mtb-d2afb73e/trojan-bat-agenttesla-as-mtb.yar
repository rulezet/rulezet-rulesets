rule Trojan_BAT_AgentTesla_AS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 6f 17 00 00 0a 0d 00 09 28 18 00 00 0a 72 53 00 00 70 28 19 00 00 0a 1f 1e 5d 5b 28 1a 00 00 0a 13 05 12 05 28 1b 00 00 0a 13 04 06 11 04 6f 1c 00 00 0a 26 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}