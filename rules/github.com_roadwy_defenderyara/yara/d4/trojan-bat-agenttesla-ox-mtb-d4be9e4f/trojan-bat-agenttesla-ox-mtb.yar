rule Trojan_BAT_AgentTesla_OX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {11 05 16 9a 28 [0-04] d0 [0-04] 28 [0-04] 28 [0-04] 74 [0-07] 28 [0-07] 72 [0-04] 17 8d [0-07] 8c [0-04] a2 14 14 28 [0-04] 09 17 da 17 d6 8d [0-04] 13 04 07 14 72 [0-04] 19 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}