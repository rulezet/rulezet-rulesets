rule Trojan_BAT_AgentTesla_NFN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 7d 00 00 0a 13 06 11 06 2c 38 06 1f 21 8c 54 00 00 01 07 1f 0e 8c 54 00 00 01 28 7e 00 00 0a 1f 5e 8c 54 00 00 01 28 7f 00 00 0a 28 7e 00 00 0a 28 77 00 00 0a 28 80 00 00 0a 28 81 00 00 0a 0a 2b 12 06 07 28 77 00 00 0a 28 80 00 00 0a 28 81 00 00 0a 0a 08 11 08 12 02 28 82 00 00 0a 13 07 11 07 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}