rule Trojan_BAT_AgentTesla_GVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 08 03 28 2b 04 00 06 9c 08 17 d6 0c 08 07 31 eb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}