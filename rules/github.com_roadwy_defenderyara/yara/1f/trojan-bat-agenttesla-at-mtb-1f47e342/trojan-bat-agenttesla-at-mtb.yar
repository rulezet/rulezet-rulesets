rule Trojan_BAT_AgentTesla_AT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 31 09 08 17 8d 03 00 00 01 25 16 11 04 8c 88 00 00 01 a2 14 28 } 		$a_01_1 = {50 00 6f 00 6b 00 65 00 72 00 31 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}