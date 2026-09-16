rule Trojan_BAT_AgentTesla_NA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 47 11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 ?? ?? 17 58 13 0f 11 0f 11 0a 8e 69 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}