rule Trojan_BAT_AgentTesla_GAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 16 13 06 2b 31 00 11 05 09 5d 13 0a 11 05 09 5b 13 0b 08 11 0a 11 0b 6f ?? 00 00 0a 13 0c 07 11 06 12 0c 28 ?? 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0d 11 0d 2d c1 } 		$a_03_1 = {13 04 16 13 05 16 13 06 2b 31 00 11 05 09 5d 13 08 11 05 09 5b 13 09 08 11 08 11 09 6f ?? 00 00 0a 13 0a 07 11 06 12 0a 28 ?? 00 00 0a 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0b 11 0b 2d c1 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}