rule Trojan_BAT_SnakeKeylogger_SGRG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SGRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 5d 91 13 07 07 11 06 08 5d 08 58 08 5d 91 11 07 61 13 08 11 06 17 58 08 5d 08 58 08 5d 13 09 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}