rule Trojan_BAT_AgentTesla_RPZ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}