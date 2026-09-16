rule Trojan_BAT_AgentTesla_RP_MTB_16{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7f 01 00 00 04 7e 01 00 00 04 8e 69 28 0d 00 00 06 73 03 00 00 06 7e 03 00 00 04 7e 02 00 00 04 6f 02 00 00 06 7e 01 00 00 04 16 8f 17 00 00 01 7e 01 00 00 04 8e 69 1f 40 12 00 28 0c 00 00 06 26 16 0b 20 88 01 00 00 0c 16 16 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}