rule Trojan_BAT_AgentTesla_MBHU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 00 35 00 4b 00 34 00 48 00 35 00 35 00 48 00 44 00 35 00 41 00 50 00 34 00 35 00 38 00 46 00 46 00 34 00 38 00 35 00 34 00 38 00 } 		$a_01_1 = {44 00 6f 00 64 00 67 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}