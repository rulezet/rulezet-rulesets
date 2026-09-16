rule Trojan_BAT_AgentTesla_STY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.STY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 12 72 37 00 00 70 7e 04 00 00 04 2b 0d 74 16 00 00 1b 2a 28 09 00 00 06 2b e7 6f 6b 00 00 0a 2b ec } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}