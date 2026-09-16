rule Trojan_BAT_AgentTesla_RS_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 28 13 00 00 0a 72 01 00 00 70 6f 14 00 00 0a 08 28 13 00 00 0a 72 01 00 00 70 6f 14 00 00 0a 8e 69 5d 91 06 08 91 61 d2 6f 15 00 00 0a 08 17 58 0c 08 06 8e 69 32 c8 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}