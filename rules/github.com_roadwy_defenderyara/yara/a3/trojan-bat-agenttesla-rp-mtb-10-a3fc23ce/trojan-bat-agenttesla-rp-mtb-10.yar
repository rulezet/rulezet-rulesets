rule Trojan_BAT_AgentTesla_RP_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 13 06 07 08 07 08 91 28 06 00 00 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d ca } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}