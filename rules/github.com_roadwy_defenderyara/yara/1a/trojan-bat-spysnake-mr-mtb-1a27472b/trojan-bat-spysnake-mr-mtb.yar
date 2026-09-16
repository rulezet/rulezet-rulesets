rule Trojan_BAT_SpySnake_MR_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 07 06 9a a2 25 17 1f 10 8c 4a 00 00 01 a2 6f ?? ?? ?? 0a a5 06 00 00 01 9c 06 17 58 0a 06 07 8e 69 fe 04 13 08 11 08 2d ad } 		$a_01_1 = {63 38 39 65 63 30 31 33 2d 31 34 66 64 2d 34 32 38 31 2d 61 61 33 62 2d 64 64 34 36 30 35 64 33 32 37 35 66 } 		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=16
 
}