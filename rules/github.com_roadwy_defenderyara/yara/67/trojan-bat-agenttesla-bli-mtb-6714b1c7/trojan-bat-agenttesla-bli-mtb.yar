rule Trojan_BAT_AgentTesla_BLI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 50 8e 69 6a 5d b7 03 50 ?? 03 50 8e 69 6a 5d b7 91 ?? ?? ?? 8e 69 6a 5d b7 91 61 03 50 ?? 17 6a d6 03 50 8e 69 6a 5d b7 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}