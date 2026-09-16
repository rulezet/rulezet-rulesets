rule Trojan_BAT_AgentTesla_EV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 91 03 07 03 6f ?? ?? ?? 0a 5d 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 9c 07 17 58 0b 07 02 8e 69 32 d6 } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {45 6e 63 72 79 70 74 44 65 63 72 79 70 74 } 		$a_81_3 = {67 70 72 6f 67 65 6a 67 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}