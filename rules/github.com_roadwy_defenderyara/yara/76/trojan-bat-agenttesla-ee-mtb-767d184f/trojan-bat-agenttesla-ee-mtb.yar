rule Trojan_BAT_AgentTesla_EE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 16 0c 2b 13 00 07 08 07 08 91 20 ?? ?? ?? 00 59 d2 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d e3 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}