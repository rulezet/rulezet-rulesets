rule Trojan_BAT_AgentTesla_DL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 13 0c 07 11 09 11 0c 08 11 08 1f 16 5d 91 61 11 0b 59 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}