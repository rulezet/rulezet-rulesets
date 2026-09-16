rule Trojan_BAT_FormBook_AFB_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 61 07 11 07 20 c0 e1 00 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 06 17 58 0a 06 20 c0 e1 00 00 fe 04 13 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}