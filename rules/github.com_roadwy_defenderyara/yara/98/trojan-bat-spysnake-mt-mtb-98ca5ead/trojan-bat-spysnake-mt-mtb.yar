rule Trojan_BAT_SpySnake_MT_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0d 2b 16 06 09 28 ?? ?? ?? 06 13 04 07 09 11 04 6f ?? ?? ?? 0a 09 18 58 0d 09 06 6f ?? ?? ?? 0a 32 e1 } 		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } 		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}