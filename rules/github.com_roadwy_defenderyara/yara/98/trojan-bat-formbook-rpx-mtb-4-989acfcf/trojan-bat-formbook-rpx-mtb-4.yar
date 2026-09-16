rule Trojan_BAT_FormBook_RPX_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 11 05 11 08 11 04 11 08 18 5a 18 6f c0 00 00 0a 1f 10 28 c1 00 00 0a d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1 } 		$a_01_1 = {58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 2d 00 58 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}