rule Trojan_BAT_AgentTesla_ABG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 ba 04 00 00 95 2e 03 16 2b 01 17 7e 03 00 00 04 1b 9a 20 d8 04 00 00 95 5a 7e 03 00 00 04 1b 9a 1f 46 95 58 61 81 07 00 00 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}