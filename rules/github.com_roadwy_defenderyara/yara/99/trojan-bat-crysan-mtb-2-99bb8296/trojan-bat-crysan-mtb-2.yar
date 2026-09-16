rule Trojan_BAT_Crysan_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 16 fe 01 0d 09 2c 14 06 07 07 b4 9c 06 07 17 d6 03 28 b7 ?? ?? 0a b4 9c 00 2b 18 07 17 fe 02 13 04 11 04 2c 0e 06 07 03 1f 63 d6 28 b7 ?? ?? 0a b4 9c } 		$a_01_1 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } 		$a_01_2 = {54 6f 53 74 72 69 6e 67 } 		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } 		$a_01_4 = {54 6f 49 6e 74 65 67 65 72 } 	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}