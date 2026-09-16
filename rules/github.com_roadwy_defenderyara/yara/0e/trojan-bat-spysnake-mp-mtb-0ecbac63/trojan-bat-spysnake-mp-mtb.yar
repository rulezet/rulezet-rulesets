rule Trojan_BAT_SpySnake_MP_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de } 		$a_01_1 = {53 61 6c 75 74 65 46 6f 72 6d 5f 4d 6f 75 73 65 44 6f 77 6e } 		$a_01_2 = {53 74 72 69 6e 67 46 6f 72 6d 61 74 45 78 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}