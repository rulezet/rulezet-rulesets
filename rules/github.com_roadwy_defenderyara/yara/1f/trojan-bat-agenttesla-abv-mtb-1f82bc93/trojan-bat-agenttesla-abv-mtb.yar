rule Trojan_BAT_AgentTesla_ABV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 7e 0f 00 00 95 2e 03 17 2b 01 16 58 7e 2d 00 00 04 17 9a 7e 2d 00 00 04 19 9a 20 7c 04 00 00 95 e0 95 7e 2d 00 00 04 19 9a 20 5f 09 00 00 95 61 7e 2d 00 00 04 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}