rule Trojan_BAT_FormBook_AFB_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 16 2d f8 2b 19 11 04 1e 25 2c e1 62 13 04 11 04 06 07 25 17 59 0b 91 58 13 04 09 17 59 0d 18 39 78 00 00 00 09 2d de } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}