rule Trojan_BAT_AgentTesla_RPF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 0b 2b 0a 00 06 02 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}