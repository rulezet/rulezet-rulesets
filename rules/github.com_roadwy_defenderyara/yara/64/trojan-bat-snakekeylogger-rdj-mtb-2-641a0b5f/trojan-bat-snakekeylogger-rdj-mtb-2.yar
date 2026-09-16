rule Trojan_BAT_SnakeKeyLogger_RDJ_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 8a 01 00 04 06 06 7b 8a 01 00 04 28 01 00 00 2b 28 02 00 00 2b 73 b6 00 00 0a 7d 8a 01 00 04 16 06 7b 8a 01 00 04 6f b7 00 00 0a 28 b8 00 00 0a 7e 8c 01 00 04 25 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}