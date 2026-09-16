rule Trojan_BAT_FormBook_AFB_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6e 08 8e 69 6a 5d d4 91 58 11 04 11 06 95 58 20 ff 00 00 00 5f 13 07 02 11 04 11 06 8f ?? 00 00 01 11 04 11 07 8f ?? 00 00 01 28 ?? 00 00 06 00 11 06 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}