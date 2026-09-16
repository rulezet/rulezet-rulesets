rule Trojan_BAT_AgentTesla_LQL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 21 02 08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 13 05 07 06 11 05 28 ?? ?? ?? 0a 9c 11 04 17 58 13 04 11 04 17 32 da } 		$a_01_1 = {42 53 54 52 4d 61 72 73 68 61 6c 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}