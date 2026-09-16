rule Trojan_BAT_AgentTesla_ID_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ID!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 06 72 63 04 00 70 72 67 04 00 70 6f 7c 00 00 0a 17 8d 57 00 00 01 25 16 1f 2d 9d 6f 7d 00 00 0a 0b 07 8e 69 8d 58 00 00 01 0c 16 13 07 2b 15 } 		$a_01_1 = {08 11 07 07 11 07 9a 1f 10 28 7e 00 00 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}