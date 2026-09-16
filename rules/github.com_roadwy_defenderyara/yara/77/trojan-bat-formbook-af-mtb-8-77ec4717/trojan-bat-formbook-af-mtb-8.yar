rule Trojan_BAT_FormBook_AF_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 1d 58 11 21 11 21 28 57 00 00 06 25 26 69 12 03 6f 31 00 00 06 25 26 } 		$a_01_1 = {48 00 56 00 70 00 4f 00 4c 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}