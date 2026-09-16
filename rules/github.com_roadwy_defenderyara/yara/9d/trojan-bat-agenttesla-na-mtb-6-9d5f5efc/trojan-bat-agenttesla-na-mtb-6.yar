rule Trojan_BAT_AgentTesla_NA_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 40 00 00 0a 0a 28 ?? 00 00 06 0b 07 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a } 		$a_01_1 = {43 68 75 61 6e 67 2e 50 72 69 6e 74 65 72 2e 43 6c 69 65 6e 74 55 6e 69 6e 73 74 61 6c 6c } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}