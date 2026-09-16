rule Trojan_BAT_AgentTesla_AKA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 0a 2b 13 09 06 07 06 91 08 06 08 8e 69 5d 91 61 d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 06 11 06 2d e1 } 		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 2e 00 49 00 4d 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}