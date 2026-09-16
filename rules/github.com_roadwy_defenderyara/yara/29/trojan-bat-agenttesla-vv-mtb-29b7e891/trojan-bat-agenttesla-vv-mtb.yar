rule Trojan_BAT_AgentTesla_VV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 58 d2 13 1b 06 11 1b 20 ff 00 00 00 5f 95 d2 13 0f 11 1a 11 0f 61 13 10 11 0a 11 06 d4 11 10 d2 9c 16 13 09 2b 23 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}