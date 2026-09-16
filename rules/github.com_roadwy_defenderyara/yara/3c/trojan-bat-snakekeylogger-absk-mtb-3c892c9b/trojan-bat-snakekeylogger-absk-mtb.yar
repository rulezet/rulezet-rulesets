rule Trojan_BAT_SnakeKeylogger_ABSK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 13 05 38 ?? ff ff ff 02 8c ?? 00 00 1b 03 04 6f ?? 01 00 0a 0b 17 13 05 38 ?? ff ff ff 06 17 58 0a 0e 04 25 5a 0d 0e 04 09 58 0d 1a 13 05 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}