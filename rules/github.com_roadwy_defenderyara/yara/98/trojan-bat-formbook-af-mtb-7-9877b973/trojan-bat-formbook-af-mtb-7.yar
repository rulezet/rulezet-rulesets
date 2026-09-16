rule Trojan_BAT_FormBook_AF_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 26 0b 28 20 00 00 0a 25 26 07 16 07 8e 69 6f 21 00 00 0a 25 26 0a 28 1d 00 00 0a 25 26 06 6f 3b 00 00 0a 0c 1f 61 6a 08 28 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}