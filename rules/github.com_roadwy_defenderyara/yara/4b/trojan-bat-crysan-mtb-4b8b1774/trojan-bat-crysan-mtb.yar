rule Trojan_BAT_Crysan_MTB{
	meta:
		description = "Trojan:BAT/Crysan!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 16 8d 4c ?? ?? 01 0c 07 7e 36 ?? ?? 04 25 2d 17 26 7e 35 ?? ?? 04 fe 06 ?? ?? ?? 06 73 5f ?? ?? 0a 25 80 36 ?? ?? 04 28 01 ?? ?? 2b 28 02 ?? ?? 2b 0c } 		$a_01_1 = {54 6f 41 72 72 61 79 } 		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } 		$a_01_3 = {44 69 72 65 63 74 6f 72 79 45 6e 74 72 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}