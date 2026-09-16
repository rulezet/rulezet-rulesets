rule Trojan_BAT_AgentTesla_RS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 09 28 55 00 00 06 28 53 00 00 06 28 52 00 00 06 28 54 00 00 06 28 51 00 00 06 28 50 00 00 06 d2 06 28 4e 00 00 06 09 17 58 0d 09 17 fe 04 13 04 11 04 2d ca } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}