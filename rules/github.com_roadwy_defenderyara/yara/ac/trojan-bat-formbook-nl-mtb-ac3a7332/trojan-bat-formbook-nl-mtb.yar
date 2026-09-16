rule Trojan_BAT_FormBook_NL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 2c 0d 00 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 26 00 06 04 58 0d 08 09 59 04 5d 0b 02 03 7e ?? ?? ?? 04 5d 07 28 ?? ?? ?? 06 9c 02 13 05 2b 00 11 05 2a } 		$a_03_1 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 0b 02 03 28 } 		$a_03_2 = {20 16 f8 00 00 0c 2b 13 00 06 08 20 00 01 00 00 28 ?? ?? ?? ?? 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}