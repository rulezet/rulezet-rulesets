rule Trojan_BAT_AgentTesla_EUL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0b 00 00 0a 0a 03 8e 69 0b 2b 0b 00 06 07 03 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 6f ?? ?? ?? 0a 2b e1 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}