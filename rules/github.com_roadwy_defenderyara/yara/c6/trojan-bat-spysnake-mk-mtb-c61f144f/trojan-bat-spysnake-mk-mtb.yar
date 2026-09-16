rule Trojan_BAT_SpySnake_MK_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de } 		$a_01_1 = {41 6e 61 6c 79 7a 65 43 6f 6e 74 72 6f 6c } 		$a_01_2 = {4e 65 74 54 6f 53 77 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}