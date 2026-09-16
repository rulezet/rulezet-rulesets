rule Trojan_BAT_AgentTesla_NE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 9c 06 17 58 0a 06 08 11 06 17 58 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}