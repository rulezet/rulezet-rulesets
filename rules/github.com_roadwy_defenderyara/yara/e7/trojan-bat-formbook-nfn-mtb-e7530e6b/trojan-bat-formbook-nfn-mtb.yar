rule Trojan_BAT_Formbook_NFN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 07 06 28 ?? ?? ?? 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 05 11 05 2d c5 } 		$a_01_1 = {47 65 74 50 69 78 65 6c } 		$a_01_2 = {52 30 35 33 35 } 		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}