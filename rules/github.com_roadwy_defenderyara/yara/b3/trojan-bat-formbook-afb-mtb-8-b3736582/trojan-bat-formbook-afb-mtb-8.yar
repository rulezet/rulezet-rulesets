rule Trojan_BAT_FormBook_AFB_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 46 00 07 11 05 07 8e 69 5d 07 11 05 07 8e 69 5d 91 08 11 05 1f 16 5d 91 61 28 ?? 00 00 0a 07 11 05 17 58 07 8e 69 5d 91 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}