rule Trojan_BAT_AgentTesla_MBCH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 08 11 05 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d dc } 		$a_03_1 = {72 66 11 00 70 72 6a 11 00 70 6f ?? ?? ?? 0a 0b 07 72 6e 11 00 70 72 72 11 00 70 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}