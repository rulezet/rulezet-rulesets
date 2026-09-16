rule Trojan_BAT_AgentTesla_RPX_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 31 01 2a 20 dc 05 00 00 28 ?? 00 00 0a 11 07 17 58 13 07 11 07 1b 32 cc } 		$a_01_1 = {42 6c 69 73 73 6d 6f 73 71 75 69 74 6f } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}