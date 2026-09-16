rule Trojan_BAT_SnakeKeylogger_RPY_MTB_6{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 6e 08 8e 69 6a 5d d4 91 13 0b 11 04 11 0b 58 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 00 09 17 58 0d 09 20 ff 00 00 00 fe 03 16 fe 01 13 0c 11 0c 2d b5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}