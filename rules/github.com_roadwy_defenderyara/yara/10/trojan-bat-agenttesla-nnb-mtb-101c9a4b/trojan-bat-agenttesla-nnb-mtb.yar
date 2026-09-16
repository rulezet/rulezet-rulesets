rule Trojan_BAT_AgentTesla_NNB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 18 7e 00 3a 00 04 a2 25 19 17 8c ?? ?? ?? 01 a2 13 01 } 		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 33 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}