rule Trojan_BAT_Snakekeylogger_ASK_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 1c 00 07 11 07 7e 04 00 00 04 11 07 91 08 11 07 09 5d 91 61 d2 9c 00 11 07 17 58 13 07 11 07 06 fe 04 13 08 11 08 2d d9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}