rule Trojan_BAT_SpySnake_ME_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 11 08 9a 1f 10 28 74 00 00 0a 8c 54 00 00 01 6f 75 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d d6 } 		$a_01_1 = {25 16 11 05 16 9a a2 25 17 11 05 17 9a a2 25 18 72 8f 04 00 70 a2 13 06 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}