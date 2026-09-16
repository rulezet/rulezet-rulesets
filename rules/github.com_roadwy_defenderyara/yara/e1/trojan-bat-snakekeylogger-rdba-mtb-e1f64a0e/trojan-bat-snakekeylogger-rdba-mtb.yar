rule Trojan_BAT_SnakeKeyLogger_RDBA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 2e 00 00 0a 6f 2f 00 00 0a 02 16 02 8e 69 6f 30 00 00 0a 2a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}