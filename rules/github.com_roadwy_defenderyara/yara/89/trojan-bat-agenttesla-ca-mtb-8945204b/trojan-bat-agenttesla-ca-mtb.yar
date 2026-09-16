rule Trojan_BAT_AgentTesla_CA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 11 16 08 11 16 91 11 04 61 20 ff 00 00 00 5f d2 9c 11 16 17 58 13 16 11 16 08 8e 69 32 e1 } 		$a_01_1 = {56 69 72 75 73 44 65 6c 65 74 65 64 } 		$a_01_2 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}