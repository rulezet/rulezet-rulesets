rule Trojan_BAT_AgentTesla_NTG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 0a 11 0a 20 08 56 4b 12 20 ?? ?? ?? 68 66 61 58 20 ?? ?? ?? 5f 5a 66 25 13 09 1f 0f 5e } 		$a_01_1 = {4e 69 73 67 63 6b 65 20 4d 61 6e 6b 61 72 69 6e } 		$a_01_2 = {53 63 72 65 65 6e 54 6f 47 69 66 20 41 70 70 6c 69 63 61 74 69 6f 6e } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}