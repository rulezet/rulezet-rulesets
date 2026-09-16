rule Trojan_BAT_AgentTesla_NZF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e ?? 00 00 04 07 91 61 d2 6f ?? 00 00 0a 07 17 58 } 		$a_01_1 = {07 7e 01 00 00 04 8e 69 32 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}