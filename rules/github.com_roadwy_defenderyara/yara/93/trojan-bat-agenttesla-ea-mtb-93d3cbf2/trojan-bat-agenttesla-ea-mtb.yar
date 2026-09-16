rule Trojan_BAT_AgentTesla_EA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 16 0d 38 19 00 00 00 08 07 09 18 6f 09 00 00 0a 1f 10 28 0a 00 00 0a 6f 0b 00 00 0a 09 18 58 0d 09 07 6f 0c 00 00 0a 32 de } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}