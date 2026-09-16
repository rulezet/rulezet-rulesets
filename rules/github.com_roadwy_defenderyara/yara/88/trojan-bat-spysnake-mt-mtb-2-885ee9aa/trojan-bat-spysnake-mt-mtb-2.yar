rule Trojan_BAT_SpySnake_MT_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de } 		$a_01_1 = {47 61 6d 65 46 6f 72 6d 5f 4b 65 79 44 6f 77 6e } 		$a_01_2 = {65 30 37 63 64 61 37 32 2d 37 31 62 33 2d 34 32 39 35 2d 38 36 35 37 2d 64 37 61 61 31 62 33 62 35 62 31 33 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}