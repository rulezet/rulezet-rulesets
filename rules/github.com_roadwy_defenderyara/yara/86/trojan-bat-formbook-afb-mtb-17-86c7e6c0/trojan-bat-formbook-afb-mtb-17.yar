rule Trojan_BAT_FormBook_AFB_MTB_17{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 3a 06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 91 61 06 07 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 07 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}