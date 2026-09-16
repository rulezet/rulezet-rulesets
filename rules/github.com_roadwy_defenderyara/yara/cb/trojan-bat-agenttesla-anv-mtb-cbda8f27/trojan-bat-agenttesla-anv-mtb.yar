rule Trojan_BAT_AgentTesla_ANV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ANV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {d4 91 11 04 11 04 07 95 11 04 08 95 58 20 ff 00 00 00 5f 95 61 ?? ?? ?? ?? ?? 9c 00 11 08 17 6a 58 13 08 11 08 11 05 8e 69 17 59 6a fe 02 16 fe 01 13 09 11 09 2d 97 } 		$a_80_1 = {47 65 74 4d 65 74 68 6f 64 } 		$a_80_2 = {47 65 74 54 79 70 65 } 		$a_80_3 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}