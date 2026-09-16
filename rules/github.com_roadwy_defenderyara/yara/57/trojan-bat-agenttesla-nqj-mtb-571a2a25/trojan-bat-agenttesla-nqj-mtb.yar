rule Trojan_BAT_AgentTesla_NQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 11 04 07 11 04 07 8e 69 5d 91 06 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d d9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}