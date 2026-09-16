rule Trojan_BAT_AgentTesla_PC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 6f 1a 00 00 0a 25 26 13 0a 11 0a 6f 58 00 00 0a 25 26 13 0b 11 0a 6f 59 00 00 0a 25 26 26 11 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}