rule Trojan_BAT_AgentTesla_RS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}