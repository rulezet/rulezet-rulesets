rule Trojan_BAT_FormBook_AAF_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 05 2b 1a 00 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9 } 		$a_01_1 = {47 00 72 00 6f 00 75 00 70 00 50 00 72 00 6f 00 6a 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}