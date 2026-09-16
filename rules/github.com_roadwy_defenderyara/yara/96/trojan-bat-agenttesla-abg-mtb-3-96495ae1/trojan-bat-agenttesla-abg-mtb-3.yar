rule Trojan_BAT_AgentTesla_ABG_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0c 08 8e 69 1f 10 59 8d ?? ?? ?? 01 0d 08 1f 10 09 16 08 8e 69 1f 10 59 28 ?? ?? ?? 0a 09 03 6b } 		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } 		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } 		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}