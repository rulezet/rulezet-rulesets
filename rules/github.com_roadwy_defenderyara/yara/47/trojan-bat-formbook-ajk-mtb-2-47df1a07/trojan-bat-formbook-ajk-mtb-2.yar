rule Trojan_BAT_Formbook_AJK_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 28 00 08 09 11 04 6f ?? ?? ?? 0a 13 0b 12 0b 28 ?? ?? ?? 0a 13 0c 07 11 05 11 0c 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 0d 11 0d 2d c8 00 09 17 58 0d 09 08 6f ?? ?? ?? 0a fe 04 13 0e 11 0e 2d ae } 		$a_01_1 = {6f 00 62 00 73 00 74 00 61 00 63 00 6c 00 65 00 5f 00 61 00 76 00 6f 00 69 00 64 00 61 00 6e 00 63 00 65 00 31 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}