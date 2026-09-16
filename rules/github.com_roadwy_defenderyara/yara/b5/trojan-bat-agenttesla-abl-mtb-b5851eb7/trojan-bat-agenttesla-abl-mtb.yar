rule Trojan_BAT_AgentTesla_ABL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 6e 31 03 16 2b 01 17 7e 05 00 00 04 20 8b 09 00 00 95 5a 7e 05 00 00 04 20 97 0c 00 00 95 58 61 80 33 00 00 04 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}