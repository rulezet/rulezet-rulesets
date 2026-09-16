rule Trojan_BAT_AgentTesla_AT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 16 00 00 06 0a 06 03 7d 0c 00 00 04 00 02 06 fe 06 17 00 00 06 73 15 00 00 0a 28 } 		$a_01_1 = {53 00 74 00 75 00 70 00 69 00 64 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}