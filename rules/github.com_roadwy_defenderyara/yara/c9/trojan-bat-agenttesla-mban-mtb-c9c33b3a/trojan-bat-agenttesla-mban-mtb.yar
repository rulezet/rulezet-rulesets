rule Trojan_BAT_AgentTesla_MBAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 03 8e 69 5d 91 06 04 1f 16 5d 91 61 28 ?? ?? ?? 06 03 04 17 58 03 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}