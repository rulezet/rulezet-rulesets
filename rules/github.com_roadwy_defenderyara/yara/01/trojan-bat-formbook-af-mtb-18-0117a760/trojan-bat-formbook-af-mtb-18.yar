rule Trojan_BAT_FormBook_AF_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 2b 42 00 07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 91 61 28 ?? ?? ?? 0a 07 11 06 17 58 07 8e 69 5d 91 } 		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 54 00 6f 00 6f 00 6c 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}