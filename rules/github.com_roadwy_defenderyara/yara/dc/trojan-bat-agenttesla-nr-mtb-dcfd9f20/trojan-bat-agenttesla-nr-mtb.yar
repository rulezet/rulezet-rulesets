rule Trojan_BAT_AgentTesla_NR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 01 1a 62 11 01 1b 63 61 11 01 58 11 03 11 00 11 03 1f 0b 63 19 5f 94 58 61 59 13 08 20 13 00 00 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}