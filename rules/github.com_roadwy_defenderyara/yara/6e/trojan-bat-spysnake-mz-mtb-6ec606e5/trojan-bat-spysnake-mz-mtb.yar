rule Trojan_BAT_SpySnake_MZ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 02 16 02 8e 69 6f 77 00 00 0a 0c 08 0d de 0b 07 2c 07 07 6f ?? ?? ?? 0a 00 dc 09 2a } 		$a_01_1 = {44 36 6e 67 65 72 6f 75 73 } 		$a_01_2 = {41 64 6a 75 73 74 6d 34 6e 74 } 		$a_01_3 = {53 6f 6d 35 74 69 6d 35 73 } 		$a_01_4 = {47 72 6f 77 69 31 67 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}