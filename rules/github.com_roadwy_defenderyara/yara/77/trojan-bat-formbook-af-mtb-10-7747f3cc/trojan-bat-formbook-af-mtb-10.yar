rule Trojan_BAT_FormBook_AF_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 16 11 01 a2 25 13 02 14 14 17 8d 04 00 00 01 25 16 17 9c 25 } 		$a_01_1 = {50 00 6f 00 72 00 61 00 6c 00 50 00 65 00 72 00 69 00 6c 00 5f 00 53 00 74 00 65 00 66 00 61 00 6e 00 54 00 69 00 63 00 75 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}