rule Trojan_BAT_AgentTesla_NTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 02 26 16 73 42 00 00 0a 0a 06 28 43 00 00 0a 03 50 6f 44 00 00 0a 6f 45 00 00 0a 0b 73 46 00 00 0a 0c 08 07 6f 47 00 00 0a 08 28 62 00 00 06 6f 48 00 00 0a 08 6f 49 00 00 0a 02 50 28 63 00 00 06 02 50 8e 69 6f 4a 00 00 0a 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}