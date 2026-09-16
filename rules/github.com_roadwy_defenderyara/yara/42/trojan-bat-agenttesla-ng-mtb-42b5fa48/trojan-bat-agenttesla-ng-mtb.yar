rule Trojan_BAT_AgentTesla_NG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 91 11 ?? 61 13 0b 07 11 ?? 07 8e 69 5d 91 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}