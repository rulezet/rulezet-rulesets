rule Trojan_BAT_FormBook_AGF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 2b 2d 00 11 05 11 07 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 09 11 06 11 09 8c 73 00 00 01 6f ?? ?? ?? 0a 26 11 07 18 58 13 07 00 11 07 11 05 6f ?? ?? ?? 0a fe 04 13 0a 11 0a 2d c2 } 		$a_01_1 = {50 00 75 00 7a 00 7a 00 6c 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}