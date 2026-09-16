rule Trojan_BAT_AgentTesla_CG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 07 03 07 91 02 04 07 04 8e b7 5d 91 04 04 07 04 8e b7 5d 91 04 8e b7 5d 91 6f } 		$a_01_1 = {61 04 07 07 1d 5d d6 04 8e b7 5d 04 8e b7 5d 91 61 9c 07 17 d6 0b 07 08 31 } 		$a_01_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 4b 00 45 00 59 00 } 		$a_01_3 = {58 6f 72 43 72 79 70 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}