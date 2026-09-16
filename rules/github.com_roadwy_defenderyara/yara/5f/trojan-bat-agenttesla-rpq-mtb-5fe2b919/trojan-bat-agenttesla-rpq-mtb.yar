rule Trojan_BAT_AgentTesla_RPQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 04 09 6f af 00 00 0a 6f a4 00 00 06 0c 02 04 09 6f af 00 00 0a 6f 9b 00 00 06 07 5a 07 18 5b 58 6c 05 09 9a 6f ce 00 00 0a 23 00 00 00 00 00 00 00 40 5b 59 04 09 6f af 00 00 0a 6f 9d 00 00 06 07 5a 07 18 5b 58 6c 05 09 9a 6f cf 00 00 0a 23 00 00 00 00 00 00 00 40 5b 59 08 06 05 09 9a 28 76 00 00 06 00 00 09 17 58 0d 09 04 6f b0 00 00 0a fe 04 13 04 11 04 2d 86 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}