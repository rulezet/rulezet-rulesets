rule Trojan_BAT_AgentTesla_CZE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d ?? ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 ?? ?? ?? ?? ?? 03 08 17 58 03 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } 		$a_01_1 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } 		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}