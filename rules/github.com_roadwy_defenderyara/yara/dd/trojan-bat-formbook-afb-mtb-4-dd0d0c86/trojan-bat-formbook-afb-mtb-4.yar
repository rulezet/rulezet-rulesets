rule Trojan_BAT_FormBook_AFB_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 15 00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}