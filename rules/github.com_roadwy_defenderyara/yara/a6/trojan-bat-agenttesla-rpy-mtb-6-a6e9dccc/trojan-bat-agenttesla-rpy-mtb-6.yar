rule Trojan_BAT_AgentTesla_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 03 00 00 0a 18 2c 03 17 2b 03 16 2b 00 2d 0d 26 7e 01 00 00 04 6f 04 00 00 0a 2b 07 80 01 00 00 04 2b ed 2a } 		$a_01_1 = {53 74 6f 70 77 61 74 63 68 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}