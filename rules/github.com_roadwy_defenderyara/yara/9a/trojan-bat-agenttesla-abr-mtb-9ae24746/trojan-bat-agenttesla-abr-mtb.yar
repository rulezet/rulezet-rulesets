rule Trojan_BAT_AgentTesla_ABR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 5a 7e 20 00 00 04 20 66 0e 00 00 95 2e 03 16 2b 01 17 17 59 7e 20 00 00 04 20 81 03 00 00 95 5f 7e 20 00 00 04 20 4c 0d 00 00 95 61 58 81 08 00 00 01 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}