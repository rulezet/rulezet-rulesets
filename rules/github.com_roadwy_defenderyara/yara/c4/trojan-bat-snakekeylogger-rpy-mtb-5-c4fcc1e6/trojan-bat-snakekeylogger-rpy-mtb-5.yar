rule Trojan_BAT_SnakeKeylogger_RPY_MTB_5{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 91 11 07 61 13 08 11 05 17 58 08 5d 13 09 1f 3f 13 11 38 0d fa ff ff 07 11 09 91 13 0a 11 08 11 0a 59 13 0b 20 ff 00 00 00 13 0c 20 ab 00 00 00 13 11 38 ed f9 ff ff 11 0b 20 00 01 00 00 58 11 0c 5f 13 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}