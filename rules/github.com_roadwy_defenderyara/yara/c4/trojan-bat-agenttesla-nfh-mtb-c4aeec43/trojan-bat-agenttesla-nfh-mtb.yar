rule Trojan_BAT_AgentTesla_NFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 07 2c 40 11 04 1f 21 8c ?? 00 00 01 09 1f 0e 8c ?? 00 00 01 28 ?? 00 00 0a 1f 5e 8c [0-40] 0a 13 04 00 2b 1b 00 11 04 } 		$a_81_1 = {49 54 49 54 49 54 49 54 49 49 54 49 54 49 54 49 54 49 54 49 54 54 49 49 54 49 54 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}