rule Trojan_BAT_AgentTesla_NG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 26 0c 1f 61 6a 08 28 ?? ?? ?? 2b 25 26 80 ?? ?? ?? 04 09 20 ?? ?? ?? 25 5a 20 ?? ?? ?? 4b 61 2b 84 06 28 ?? ?? ?? 0a 0b 09 20 ?? ?? ?? 4a 5a 20 84 ?? ?? ?? 61 38 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}