rule Trojan_BAT_AgentTesla_ABW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 1f 0a 00 00 95 2e 03 16 2b 01 17 7e 25 00 00 04 20 f0 09 00 00 95 5a 7e 25 00 00 04 20 35 0d 00 00 95 58 61 80 26 00 00 04 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}