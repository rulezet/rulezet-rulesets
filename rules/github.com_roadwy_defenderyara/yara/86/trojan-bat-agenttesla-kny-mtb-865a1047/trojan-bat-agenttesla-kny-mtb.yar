rule Trojan_BAT_AgentTesla_KNY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 20 00 01 00 00 5d 94 13 08 11 07 06 02 06 91 11 08 61 d2 9c 06 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}