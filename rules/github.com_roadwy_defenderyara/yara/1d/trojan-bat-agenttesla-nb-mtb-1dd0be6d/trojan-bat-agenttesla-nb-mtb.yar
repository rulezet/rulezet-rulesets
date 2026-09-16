rule Trojan_BAT_AgentTesla_NB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 11 04 17 58 13 04 11 04 20 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}