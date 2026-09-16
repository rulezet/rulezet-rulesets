rule Trojan_BAT_AgentTesla_ABU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 2e 03 16 2b 01 17 17 59 7e 2e 00 00 04 17 9a 20 ae 02 00 00 95 5f 7e 2e 00 00 04 17 9a 20 08 02 00 00 95 61 58 81 0c 00 00 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}