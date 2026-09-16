rule Trojan_BAT_AgentTesla_MBWD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 13 ?? 11 ?? 19 32 } 		$a_01_1 = {4c 00 6f 00 61 00 64 } 		$a_01_2 = {79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}