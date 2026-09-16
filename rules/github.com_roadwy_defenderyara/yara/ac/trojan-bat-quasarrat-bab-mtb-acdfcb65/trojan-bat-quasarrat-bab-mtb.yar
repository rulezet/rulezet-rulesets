rule Trojan_BAT_QuasarRAT_BAB_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 07 ?? ?? 00 00 0a ?? ?? 00 00 0a 0c ?? ?? 00 00 0a 08 ?? ?? 00 00 0a 0d 09 ?? ?? 00 00 0a 14 14 ?? ?? 00 00 0a 26 2a } 		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_3 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}