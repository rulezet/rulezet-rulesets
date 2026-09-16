rule Trojan_BAT_AgentTesla_NNL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 3f 05 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a } 		$a_01_1 = {4d 47 2e 4f 66 66 69 63 65 2e 45 64 69 74 6f 72 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}