rule Trojan_BAT_AgentTesla_RB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 08 1e 58 1d 59 02 8e 69 5d 91 59 20 ?? ?? ?? 00 58 18 58 20 ?? ?? ?? 00 5d d2 9c 08 16 2d 02 17 58 } 		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}