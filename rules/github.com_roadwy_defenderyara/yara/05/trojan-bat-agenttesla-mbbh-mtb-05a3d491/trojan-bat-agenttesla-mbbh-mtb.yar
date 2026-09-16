rule Trojan_BAT_AgentTesla_MBBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 6d 03 00 00 95 5f 7e 45 00 00 04 20 87 09 00 00 95 61 58 13 39 38 a8 04 00 00 11 39 7e 45 00 00 04 20 6f 10 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}