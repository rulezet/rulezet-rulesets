rule Trojan_BAT_AgentTesla_MBAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 06 8e 69 5d 06 11 05 06 8e 69 5d 91 07 11 05 1f 16 5d 91 61 28 ?? ?? ?? 0a 06 11 05 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}