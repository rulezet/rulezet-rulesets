rule Trojan_BAT_SnakeKeyLogger_AMX_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b de 22 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}