rule Trojan_BAT_AgentTesla_CXS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 9a 13 08 09 11 08 1f 10 28 ?? ?? ?? ?? b4 6f ?? ?? ?? ?? 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09 2d } 		$a_01_1 = {36 00 36 00 5f 00 4e 00 75 00 64 00 65 00 5f 00 50 00 68 00 6f 00 74 00 6f 00 73 00 5f 00 5f 00 5f 00 32 00 32 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}