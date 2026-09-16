rule Trojan_BAT_AgentTesla_NCA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 08 11 04 91 07 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 02 7b 03 00 00 04 32 e2 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}