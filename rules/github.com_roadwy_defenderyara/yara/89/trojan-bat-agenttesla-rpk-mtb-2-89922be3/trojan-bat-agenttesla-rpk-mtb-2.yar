rule Trojan_BAT_AgentTesla_RPK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 17 8d 6c 00 00 01 25 16 08 17 8d 17 00 00 01 25 16 11 04 8c 59 00 00 01 a2 14 28 a8 00 00 0a 28 87 00 00 0a 1f 10 28 ae 00 00 0a 9c 6f af 00 00 0a 00 11 04 17 d6 13 04 00 11 04 20 00 7c 00 00 fe 04 13 06 11 06 2d b7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}