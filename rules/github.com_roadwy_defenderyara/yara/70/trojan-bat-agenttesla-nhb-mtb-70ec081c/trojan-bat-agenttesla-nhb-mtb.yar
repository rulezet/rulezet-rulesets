rule Trojan_BAT_AgentTesla_NHB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 32 05 00 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a } 		$a_01_1 = {4d 47 2e 4f 66 66 69 63 65 2e 44 69 61 67 72 61 6d } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}