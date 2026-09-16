rule Trojan_BAT_AgentTesla_SB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 06 91 20 ?? ?? ?? ?? 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? ?? 8e 69 fe 04 0b 07 2d d7 } 		$a_80_1 = {6e 61 64 6a 6f 64 6f 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}