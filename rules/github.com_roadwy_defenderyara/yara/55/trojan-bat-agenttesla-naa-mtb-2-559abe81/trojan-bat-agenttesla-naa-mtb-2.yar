rule Trojan_BAT_AgentTesla_NAA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 7e 03 00 00 04 28 ?? 00 00 0a 0c 07 08 16 08 8e 69 73 ?? 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 00 06 7e ?? 00 00 04 } 		$a_01_1 = {47 61 6d 65 4d 6f 6e 50 52 4f 4b 49 4c 4c } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}