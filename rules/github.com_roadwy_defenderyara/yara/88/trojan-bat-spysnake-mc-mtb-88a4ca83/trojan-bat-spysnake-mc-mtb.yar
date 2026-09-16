rule Trojan_BAT_SpySnake_MC_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 09 17 59 11 04 a2 00 09 17 58 0d 09 03 6f ?? ?? ?? 06 fe 02 16 fe 01 13 06 11 06 3a 51 ff ff ff } 		$a_01_1 = {46 61 72 30 65 72 } 		$a_01_2 = {53 63 6f 32 65 } 		$a_01_3 = {50 61 30 6b 61 67 65 } 		$a_01_4 = {43 6f 6d 70 6c 61 34 6e 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}