rule Trojan_BAT_AgentTesla_AMBH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 18 6f ?? 00 00 0a 00 06 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}