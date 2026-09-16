rule Trojan_BAT_AgentTesla_NWZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 } 		$a_01_1 = {50 00 35 00 33 00 59 00 53 00 43 00 59 00 52 00 42 00 56 00 48 00 48 00 55 00 50 00 38 00 47 00 34 00 37 00 42 00 37 00 35 00 59 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}