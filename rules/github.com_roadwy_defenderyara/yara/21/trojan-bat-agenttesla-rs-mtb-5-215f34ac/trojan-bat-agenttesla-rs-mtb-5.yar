rule Trojan_BAT_AgentTesla_RS_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 12 06 28 1a 00 00 0a 08 06 18 6f 1b 00 00 0a 11 04 28 1c 00 00 0a 13 07 07 06 11 07 6f 1d 00 00 0a de 0b } 		$a_01_1 = {07 6f 20 00 00 0a 28 01 00 00 2b 13 05 1c 2c a5 11 05 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}