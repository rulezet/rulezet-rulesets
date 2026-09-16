rule Trojan_BAT_QuasarRAT_BAC_MTB_2{
	meta:
		description = "Trojan:BAT/QuasarRAT.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 ?? ?? 00 00 0a 17 73 29 00 00 0a 13 07 11 07 08 16 08 8e 69 ?? ?? 00 00 0a 11 07 ?? ?? 00 00 0a de 0c 11 07 2c 07 11 07 ?? ?? 00 00 0a dc 11 06 ?? ?? 00 00 0a 13 08 de 18 11 06 2c 07 11 06 ?? ?? 00 00 0a dc } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}