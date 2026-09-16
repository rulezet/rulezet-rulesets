rule Trojan_BAT_AgentTesla_NLA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 17 11 09 28 89 00 00 06 11 0d 20 ?? ?? ?? 4f 5a 20 13 20 04 f7 61 2b cb } 		$a_01_1 = {50 72 6f 67 72 61 6d 49 6e 73 74 61 6c 6c 65 72 2e 49 6e 74 65 72 66 61 63 65 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}