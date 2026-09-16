rule Trojan_BAT_AgentTesla_NZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 fe 0e 16 00 fe 0c 12 00 fe 0c 12 00 59 fe 0c 16 00 61 fe 0c 12 00 58 fe 0e 15 00 fe 0c 11 00 fe 0c 11 00 20 0b } 		$a_01_1 = {53 55 63 36 39 54 4e 57 55 4f 6e 5a 42 52 61 51 71 51 2e 6b 63 70 49 59 52 5a 49 30 42 36 57 39 75 49 66 53 77 } 		$a_01_2 = {52 6b 4d 52 6a 4a 5a 49 5a 5a 72 57 42 61 39 57 56 52 64 00 50 51 62 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}