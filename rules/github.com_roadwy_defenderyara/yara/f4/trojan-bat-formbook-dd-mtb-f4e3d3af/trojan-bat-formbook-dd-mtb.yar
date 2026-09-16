rule Trojan_BAT_Formbook_DD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {00 06 07 16 20 ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? ?? ?? ?? ?? ?? 16 fe 02 13 05 11 05 2d } 		$a_80_1 = {47 5a 49 44 45 4b 4b 4b 4b } 		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}