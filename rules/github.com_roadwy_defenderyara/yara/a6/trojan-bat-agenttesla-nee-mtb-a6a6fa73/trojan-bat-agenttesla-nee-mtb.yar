rule Trojan_BAT_AgentTesla_NEE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {da 17 d6 8d 15 00 00 01 13 05 02 02 8e b7 17 da 91 0a 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0c 12 05 } 		$a_01_1 = {41 44 49 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}