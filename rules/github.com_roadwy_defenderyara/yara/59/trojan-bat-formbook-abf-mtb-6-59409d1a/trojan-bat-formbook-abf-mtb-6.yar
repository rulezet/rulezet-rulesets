rule Trojan_BAT_FormBook_ABF_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 00 00 0a 13 05 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 17 13 04 2b a6 11 04 17 33 12 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 18 13 04 2b 8f 07 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 58 0d 16 13 04 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}