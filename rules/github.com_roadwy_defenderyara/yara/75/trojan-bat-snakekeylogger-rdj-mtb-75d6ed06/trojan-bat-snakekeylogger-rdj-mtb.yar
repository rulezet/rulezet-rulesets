rule Trojan_BAT_SnakeKeyLogger_RDJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 7e 08 00 00 04 6f 25 00 00 0a 02 16 04 8e 69 6f 26 00 00 0a 0a 06 0b } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}