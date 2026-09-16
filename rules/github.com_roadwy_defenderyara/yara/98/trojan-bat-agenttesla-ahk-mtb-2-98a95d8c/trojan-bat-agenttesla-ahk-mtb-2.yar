rule Trojan_BAT_AgentTesla_AHK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 6f 03 00 00 0a 13 26 11 0a 11 26 11 10 59 61 13 0a 11 10 19 11 0a 58 1e 63 59 13 10 11 0b 6f 34 00 00 06 2d d9 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}