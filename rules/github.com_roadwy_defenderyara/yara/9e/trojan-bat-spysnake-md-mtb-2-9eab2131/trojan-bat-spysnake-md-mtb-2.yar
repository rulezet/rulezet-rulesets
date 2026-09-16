rule Trojan_BAT_SpySnake_MD_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 17 da 0c 2b 13 06 07 08 93 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 15 d6 0c 08 16 2f e9 } 		$a_01_1 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 } 		$a_01_2 = {67 65 74 5f 57 65 62 42 72 6f 77 73 65 72 } 		$a_01_3 = {46 69 6c 65 44 6f 77 6e 6c 6f 61 64 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}