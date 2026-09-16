rule Trojan_BAT_AgentTesla_RP_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 13 07 07 11 05 11 07 20 ff 00 00 00 5f 28 86 00 00 0a 9c 00 11 05 17 58 13 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}