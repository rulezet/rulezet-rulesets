rule Trojan_BAT_AgentTesla_RP_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 00 70 6f ?? 00 00 0a 11 05 1f 16 5d 91 13 06 11 05 17 58 08 5d } 		$a_01_1 = {02 07 11 05 91 11 06 61 11 08 28 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}