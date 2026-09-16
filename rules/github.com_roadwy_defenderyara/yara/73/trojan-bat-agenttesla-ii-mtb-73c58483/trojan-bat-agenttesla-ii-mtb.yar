rule Trojan_BAT_AgentTesla_II_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.II!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {11 07 07 11 13 20 ?? ?? ?? ff 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 9e 11 07 07 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 07 07 94 1f 9c 32 0e 11 07 07 94 1f 64 30 06 11 11 17 58 13 11 07 17 58 0b 07 11 07 8e 69 32 ae } 		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}