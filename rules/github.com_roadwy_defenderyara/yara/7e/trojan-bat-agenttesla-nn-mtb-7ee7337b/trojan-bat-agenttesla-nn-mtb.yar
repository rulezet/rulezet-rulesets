rule Trojan_BAT_AgentTesla_NN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e ?? ?? ?? ?? 61 13 0f 07 11 0a ?? ?? ?? ?? 59 11 08 5d d2 9c 00 11 07 17 58 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}