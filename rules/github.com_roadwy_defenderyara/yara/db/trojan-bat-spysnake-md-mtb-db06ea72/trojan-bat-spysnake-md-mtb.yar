rule Trojan_BAT_SpySnake_MD_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 07 11 09 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d db } 		$a_03_1 = {25 16 11 06 16 9a a2 25 17 11 06 17 9a a2 25 18 72 ?? ?? ?? 70 a2 13 07 11 05 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}