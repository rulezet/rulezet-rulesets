rule Trojan_BAT_Formbook_AJK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 49 00 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 09 17 58 07 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 07 11 07 2d aa } 		$a_01_1 = {43 00 75 00 61 00 48 00 61 00 6e 00 67 00 44 00 54 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}