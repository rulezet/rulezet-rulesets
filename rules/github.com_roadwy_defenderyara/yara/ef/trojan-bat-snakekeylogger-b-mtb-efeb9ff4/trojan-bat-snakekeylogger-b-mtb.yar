rule Trojan_BAT_SnakeKeylogger_B_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d b2 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f 65 01 00 0a 1f 10 28 66 01 00 0a } 		$a_01_1 = {61 34 63 39 39 35 34 63 2d 39 37 64 39 2d 34 66 31 37 2d 61 32 32 36 2d 31 35 65 61 38 64 64 64 39 33 33 31 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}