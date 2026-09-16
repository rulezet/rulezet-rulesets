rule Trojan_BAT_AgentTesla_LTN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 29 00 09 11 04 11 05 28 ?? ?? ?? 06 13 09 11 09 28 ?? ?? ?? 0a 13 0a 08 11 04 11 0a d2 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d cc } 		$a_81_1 = {47 65 74 50 69 78 65 6c } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}