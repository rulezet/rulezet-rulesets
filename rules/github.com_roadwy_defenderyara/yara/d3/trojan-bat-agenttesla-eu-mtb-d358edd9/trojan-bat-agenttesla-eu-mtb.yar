rule Trojan_BAT_AgentTesla_EU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {0d 08 09 61 d1 13 04 06 11 04 6f ?? ?? ?? 0a 26 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d ce 90 09 0d 00 02 07 6f ?? ?? ?? 0a 0c 7e ?? ?? ?? 04 } 		$a_81_1 = {41 45 53 5f 44 65 63 72 79 70 74 } 		$a_81_2 = {45 6e 63 72 79 70 74 44 65 63 72 79 70 74 } 		$a_81_3 = {58 6f 72 4b 65 79 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}