rule Trojan_BAT_AgentTesla_MBFE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 07 8e 69 0c 16 0a 2b ?? 06 08 5d 0d 06 17 58 08 5d } 		$a_01_1 = {91 61 07 11 09 91 59 20 00 01 00 00 58 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}