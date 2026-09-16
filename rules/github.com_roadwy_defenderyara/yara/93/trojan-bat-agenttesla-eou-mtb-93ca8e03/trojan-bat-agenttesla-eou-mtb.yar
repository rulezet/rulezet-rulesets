rule Trojan_BAT_AgentTesla_EOU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 20 00 60 00 00 5d 11 01 11 03 20 00 60 00 00 5d 91 11 02 11 03 1f 16 5d ?? ?? ?? ?? ?? 61 11 01 11 03 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}