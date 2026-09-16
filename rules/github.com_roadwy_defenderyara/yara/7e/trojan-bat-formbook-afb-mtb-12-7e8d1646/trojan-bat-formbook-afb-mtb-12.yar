rule Trojan_BAT_FormBook_AFB_MTB_12{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 11 0f 58 19 5d 13 11 18 11 0f 58 19 5d 13 12 19 8d ?? 00 00 01 13 13 11 13 16 12 0c 28 ?? 00 00 0a 9c 11 13 17 12 0c 28 ?? 00 00 0a 9c 11 13 18 12 0c 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}