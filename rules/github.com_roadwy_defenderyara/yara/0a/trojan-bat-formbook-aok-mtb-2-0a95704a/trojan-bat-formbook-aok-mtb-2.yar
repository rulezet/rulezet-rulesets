rule Trojan_BAT_Formbook_AOK_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 13 00 06 07 06 07 91 ?? ?? ?? ?? ?? 59 d2 9c 07 17 58 0b 00 07 06 8e 69 fe 01 16 fe 01 0c 08 } 		$a_01_1 = {71 00 61 00 74 00 61 00 72 00 69 00 73 00 2e 00 61 00 67 00 65 00 6e 00 63 00 79 00 2f 00 34 00 32 00 33 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}