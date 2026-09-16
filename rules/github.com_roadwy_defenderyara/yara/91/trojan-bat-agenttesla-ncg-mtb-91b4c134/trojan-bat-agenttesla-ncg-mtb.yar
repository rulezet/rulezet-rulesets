rule Trojan_BAT_AgentTesla_NCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 2b 02 11 04 11 05 6f 34 00 00 0a 13 08 12 08 28 35 00 00 0a 28 36 00 00 0a 16 08 09 1a 28 37 00 00 0a 09 1a 58 0d 11 05 17 58 13 05 11 05 06 32 d0 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}