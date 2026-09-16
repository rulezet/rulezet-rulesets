rule Trojan_BAT_SnakeKeylogger_MA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 0d 74 03 00 00 1b 2a 28 ?? 00 00 06 2b e7 6f ?? 00 00 0a 2b ec 90 0a 25 00 2b 12 72 ?? 00 00 70 7e ?? 00 00 04 } 		$a_03_1 = {1e 2c 18 2b 18 2b 1d 2b 22 ?? ?? 09 26 12 00 ?? 2d 07 26 de 2a 2b 1b 2b f4 2b 1a 2b f6 28 ?? 00 00 06 2b e1 28 0f 00 00 06 2b dc 28 10 00 00 06 2b d7 0a 2b e2 28 11 00 00 06 2b df 26 de } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}