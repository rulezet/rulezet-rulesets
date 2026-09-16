rule Trojan_BAT_AgentTesla_FO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 0b 00 00 0a 13 01 38 00 00 00 00 00 11 01 11 0c 6f 0c 00 00 0a 17 73 0d 00 00 0a 13 0b 38 00 00 00 00 00 11 0b 02 16 02 8e 69 6f 0e 00 00 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}