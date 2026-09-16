rule Trojan_BAT_AgentTesla_NU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 28 ?? ?? ?? 06 03 04 17 58 20 00 3a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 3a 00 00 5d 07 d2 9c 03 0c 2b 00 } 		$a_01_1 = {35 00 50 00 48 00 34 00 37 00 35 00 4e 00 47 00 42 00 38 00 59 00 45 00 46 00 39 00 34 00 34 00 5a 00 46 00 43 00 49 00 35 00 41 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}