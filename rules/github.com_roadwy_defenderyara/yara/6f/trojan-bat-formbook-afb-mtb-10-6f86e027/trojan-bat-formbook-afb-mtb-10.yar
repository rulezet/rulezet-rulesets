rule Trojan_BAT_FormBook_AFB_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 16 13 08 2b 26 16 13 09 28 ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 11 09 2f 0b 09 13 0a 11 0a 28 ?? 00 00 06 26 11 08 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}