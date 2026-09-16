rule Trojan_BAT_FormBook_AGF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 27 00 07 11 04 11 05 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 8c 77 00 00 01 6f ?? ?? ?? 0a 26 00 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a fe 04 13 07 11 07 2d c9 } 		$a_01_1 = {41 00 69 00 72 00 46 00 72 00 65 00 69 00 67 00 68 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}