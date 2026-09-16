rule Trojan_BAT_AgentTesla_BFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {04 02 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 06 28 ?? ?? ?? 06 26 09 18 25 2c 92 d6 0d 09 08 31 be 7e ?? ?? ?? 04 07 28 ?? ?? ?? 06 0a 2b 00 06 2a 02 } 		$a_81_1 = {4b 79 67 6f 2e 64 6c 6c } 		$a_81_2 = {47 61 72 72 69 78 2e 45 78 70 6c 6f 72 65 72 31 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}