rule Trojan_BAT_AgentTesla_NZV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } 		$a_81_1 = {47 34 44 35 34 43 37 44 34 38 41 35 37 45 34 37 59 38 37 48 42 34 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}