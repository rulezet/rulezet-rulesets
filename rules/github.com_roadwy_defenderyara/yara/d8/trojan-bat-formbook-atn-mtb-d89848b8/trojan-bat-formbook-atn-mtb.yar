rule Trojan_BAT_FormBook_ATN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 44 06 1f 16 5d 13 07 11 04 11 05 28 ?? 00 00 2b 11 06 28 ?? 00 00 2b 28 ?? 00 00 2b 11 07 91 13 08 06 17 58 09 5d 13 09 07 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a 07 06 11 0a d2 9c 06 17 58 0a 06 07 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}