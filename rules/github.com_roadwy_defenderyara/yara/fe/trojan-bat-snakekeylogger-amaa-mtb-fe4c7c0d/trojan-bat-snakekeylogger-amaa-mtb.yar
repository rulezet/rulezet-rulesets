rule Trojan_BAT_SnakeKeylogger_AMAA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 20 00 01 00 00 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}