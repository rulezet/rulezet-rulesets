rule Trojan_BAT_SnakeKeylogger_RPY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 0a 03 04 17 58 06 5d 91 2a } 		$a_01_1 = {03 04 61 05 59 20 00 01 00 00 58 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}