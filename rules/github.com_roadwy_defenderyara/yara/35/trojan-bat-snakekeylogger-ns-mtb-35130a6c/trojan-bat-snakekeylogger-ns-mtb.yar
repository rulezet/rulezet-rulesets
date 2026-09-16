rule Trojan_BAT_SnakeKeylogger_NS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 6f 1a 00 00 0a 08 07 6f 1b 00 00 0a 08 6f 1c 00 00 0a 0d 73 1d 00 00 0a 25 09 03 16 03 8e 69 6f 1e 00 00 0a 6f 1f 00 00 0a 13 04 } 		$a_01_1 = {28 05 00 00 0a 03 6f 06 00 00 0a 0a 06 14 28 07 00 00 0a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}