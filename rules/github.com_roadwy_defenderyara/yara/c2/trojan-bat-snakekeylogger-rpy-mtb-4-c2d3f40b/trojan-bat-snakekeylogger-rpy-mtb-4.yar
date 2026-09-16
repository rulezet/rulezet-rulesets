rule Trojan_BAT_SnakeKeylogger_RPY_MTB_4{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 14 11 14 11 13 1f 16 5d 91 13 15 07 11 13 91 11 15 61 13 16 11 13 17 58 08 5d 13 17 07 11 17 91 13 18 11 16 11 18 59 13 19 20 ff 00 00 00 13 1a 11 19 20 00 01 00 00 58 11 1a 5f 13 1b 07 11 13 11 1b d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}