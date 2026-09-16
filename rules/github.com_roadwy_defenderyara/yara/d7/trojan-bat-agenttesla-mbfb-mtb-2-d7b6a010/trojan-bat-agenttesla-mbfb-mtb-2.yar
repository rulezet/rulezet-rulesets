rule Trojan_BAT_AgentTesla_MBFB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 03 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 2a } 		$a_01_1 = {35 65 38 62 35 62 39 36 34 31 39 30 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}