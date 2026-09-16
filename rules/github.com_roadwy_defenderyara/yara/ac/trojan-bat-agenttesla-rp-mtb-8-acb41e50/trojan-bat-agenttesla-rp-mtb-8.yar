rule Trojan_BAT_AgentTesla_RP_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0c 00 00 06 28 03 00 00 06 2a 00 13 30 06 00 ?? ?? 00 00 02 00 00 11 d0 01 00 00 02 28 } 		$a_01_1 = {73 65 74 5f 50 61 64 64 69 6e 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}