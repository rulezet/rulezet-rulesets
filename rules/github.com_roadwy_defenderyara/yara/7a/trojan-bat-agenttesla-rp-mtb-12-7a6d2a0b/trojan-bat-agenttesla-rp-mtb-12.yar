rule Trojan_BAT_AgentTesla_RP_MTB_12{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 07 08 91 28 0e 00 00 06 08 1f 16 5d 91 61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 13 05 11 05 2d c6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}