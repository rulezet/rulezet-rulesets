rule Trojan_BAT_AgentTesla_RP_MTB_18{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 8f 05 00 00 01 25 71 05 00 00 01 11 07 02 58 04 59 20 ff 00 00 00 5f d2 61 d2 81 05 00 00 01 11 12 1f 79 93 20 83 18 00 00 59 13 10 38 } 		$a_01_1 = {61 02 61 0a 7e 1a 00 00 04 0c 08 74 03 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 a0 00 00 00 91 11 0f 1f 34 91 59 13 0e 38 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}