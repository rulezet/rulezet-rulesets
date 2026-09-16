rule Trojan_BAT_AgentTesla_MB_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 31 00 00 00 06 00 00 00 06 00 00 00 0f } 		$a_01_1 = {13 05 00 11 04 13 08 16 13 09 2b 15 11 08 11 09 9a 13 0a 11 0a 6f 27 00 00 0a 00 11 09 17 58 13 09 11 09 11 08 8e 69 32 e3 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}