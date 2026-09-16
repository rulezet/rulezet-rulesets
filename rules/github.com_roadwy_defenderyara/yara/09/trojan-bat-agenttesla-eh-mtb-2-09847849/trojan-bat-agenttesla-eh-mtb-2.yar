rule Trojan_BAT_AgentTesla_EH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 19 5a 11 05 58 08 6f ?? ?? ?? 06 17 59 11 04 58 08 6f ?? ?? ?? 06 17 59 11 05 58 73 ?? ?? ?? 06 a2 00 11 05 17 58 13 05 11 05 19 fe 04 13 06 11 06 2d c9 } 		$a_81_1 = {42 61 74 74 6c 65 53 68 69 70 } 		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}