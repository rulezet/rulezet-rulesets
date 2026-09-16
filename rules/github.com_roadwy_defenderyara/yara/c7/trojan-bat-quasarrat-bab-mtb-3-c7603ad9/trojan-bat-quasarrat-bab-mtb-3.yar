rule Trojan_BAT_QuasarRAT_BAB_MTB_3{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0d 00 09 07 ?? ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 00 11 04 06 16 06 8e 69 ?? ?? 00 00 0a 00 00 de 14 11 04 14 fe 01 13 06 11 06 2d 08 11 04 ?? ?? 00 00 0a 00 dc 00 09 ?? ?? 00 00 0a 13 05 de 30 09 14 fe 01 13 06 11 06 2d 07 09 ?? ?? 00 00 0a 00 dc } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {49 6e 76 6f 6b 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}