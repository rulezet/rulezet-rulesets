rule Trojan_BAT_AgentTesla_ABP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 17 59 7e 2c 00 00 04 20 04 0a 00 00 95 5f 7e 2c 00 00 04 20 88 08 00 00 95 61 58 81 07 00 00 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}