rule Trojan_BAT_SpySnake_ML_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 19 07 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 18 58 0c 08 06 32 e3 } 		$a_01_1 = {57 15 02 08 09 0b 00 00 00 5a a4 00 00 16 00 00 01 00 00 00 31 } 		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_3 = {65 61 61 62 37 32 62 63 2d 61 35 39 34 2d 34 39 62 64 2d 39 37 31 61 2d 36 39 36 62 64 63 65 39 33 62 39 66 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}