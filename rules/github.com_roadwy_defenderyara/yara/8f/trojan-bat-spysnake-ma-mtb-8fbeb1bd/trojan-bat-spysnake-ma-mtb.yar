rule Trojan_BAT_SpySnake_MA_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 06 17 58 0a 00 09 17 58 0d 09 20 00 d0 00 00 fe 04 13 06 11 06 2d a8 } 		$a_01_1 = {66 69 72 73 74 43 6c 69 63 6b 65 64 } 		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_01_3 = {54 69 6d 65 72 31 5f 54 69 63 6b } 		$a_01_4 = {4d 6f 76 65 6d 65 6e 74 54 6f 44 6f 77 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}