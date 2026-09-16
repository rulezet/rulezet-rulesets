rule Trojan_BAT_SnakeKeylogger_ABSM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 1c 11 1d 6f ?? 00 00 0a 13 24 11 0c 11 1e 12 24 28 ?? 00 00 0a 6f ?? 00 00 0a 12 24 28 ?? 00 00 0a 13 25 12 24 28 ?? 00 00 0a 13 26 12 24 28 ?? 00 00 0a 13 27 11 25 11 26 58 11 27 58 13 28 11 28 1f 1f 61 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}