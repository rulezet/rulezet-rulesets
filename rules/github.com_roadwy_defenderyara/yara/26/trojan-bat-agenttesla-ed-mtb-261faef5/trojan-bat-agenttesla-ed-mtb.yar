rule Trojan_BAT_AgentTesla_ED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 0a 02 8e 69 8d ?? ?? ?? ?? 0b 16 0c 2b 15 00 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d df } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}