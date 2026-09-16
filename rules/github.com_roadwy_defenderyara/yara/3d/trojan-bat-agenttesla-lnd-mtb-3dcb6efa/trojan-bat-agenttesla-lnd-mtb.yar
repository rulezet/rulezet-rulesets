rule Trojan_BAT_AgentTesla_LND_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 6c 23 ?? ?? ?? ?? ?? ?? ?? 3f 5b 28 ?? ?? ?? 0a b7 28 ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 13 05 07 11 05 6f ?? ?? ?? 0a 26 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d b7 } 		$a_01_1 = {00 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}