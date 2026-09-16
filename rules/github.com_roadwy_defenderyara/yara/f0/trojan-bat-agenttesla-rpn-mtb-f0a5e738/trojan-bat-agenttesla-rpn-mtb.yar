rule Trojan_BAT_AgentTesla_RPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 06 08 06 8e 69 5d 91 02 08 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}