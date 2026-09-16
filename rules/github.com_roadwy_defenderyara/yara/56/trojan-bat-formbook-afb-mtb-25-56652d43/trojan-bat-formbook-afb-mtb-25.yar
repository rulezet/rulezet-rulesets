rule Trojan_BAT_FormBook_AFB_MTB_25{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 59 00 20 00 01 00 00 13 0b 11 0a 17 58 13 0c 11 0a 20 00 56 01 00 5d 13 0d 11 0c 20 00 56 01 00 5d 13 0e 11 04 11 0e 91 11 0b 58 13 0f 11 04 11 0d 91 13 10 11 05 11 0a 1f 16 5d 91 13 11 11 10 11 11 61 13 12 11 04 11 0d 11 12 11 0f 59 11 0b 5d d2 9c 00 11 0a 17 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}