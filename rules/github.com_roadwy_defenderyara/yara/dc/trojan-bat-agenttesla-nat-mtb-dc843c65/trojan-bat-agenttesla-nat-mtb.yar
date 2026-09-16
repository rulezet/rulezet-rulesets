rule Trojan_BAT_AgentTesla_NAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 2e 00 00 0a 02 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 19 2d 03 26 de 06 0a 2b fb } 		$a_01_1 = {43 75 74 73 6f 67 67 77 67 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}