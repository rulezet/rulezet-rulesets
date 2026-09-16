rule Trojan_BAT_AgentTesla_SW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 00 01 00 00 13 07 11 06 17 58 13 08 11 06 20 00 cc 00 00 5d 13 09 11 08 20 00 cc 00 00 5d 13 0a 07 11 09 91 13 0b 1f 16 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}