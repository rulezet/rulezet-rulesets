rule Trojan_BAT_FormBook_ACM_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de } 		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 73 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}