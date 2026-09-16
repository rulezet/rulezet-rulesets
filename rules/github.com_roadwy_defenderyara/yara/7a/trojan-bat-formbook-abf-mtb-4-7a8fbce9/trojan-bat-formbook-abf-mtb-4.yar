rule Trojan_BAT_FormBook_ABF_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 0b 08 11 09 11 0b 6f ?? 00 00 06 12 0b 28 ?? 00 00 0a 13 0c 12 0b 28 ?? 00 00 0a 13 0d 12 0b 28 ?? 00 00 0a 13 0e 11 0c 11 04 11 05 28 ?? 00 00 06 13 0c 11 0d 11 04 11 06 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}