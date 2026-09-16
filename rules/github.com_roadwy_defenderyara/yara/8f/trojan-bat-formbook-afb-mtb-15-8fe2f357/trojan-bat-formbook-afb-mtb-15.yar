rule Trojan_BAT_FormBook_AFB_MTB_15{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 2b 3a 11 07 11 06 6f ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 13 05 11 05 6c 03 28 ?? 00 00 0a 59 28 ?? 00 00 0a b7 0a 06 28 ?? 00 00 0a 0c 07 08 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}