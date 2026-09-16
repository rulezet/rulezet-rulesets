rule Trojan_BAT_AgentTesla_ANK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0d 91 13 0e 07 17 58 11 09 5d 13 0f 08 07 02 08 07 91 11 0e 61 08 11 0f 91 59 28 34 00 00 06 28 4b 00 00 0a 9c 07 17 58 0b } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}