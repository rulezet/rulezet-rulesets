rule Trojan_BAT_FormBook_AFB_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 07 11 08 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 16 61 d2 13 0a 12 09 28 ?? 00 00 0a 16 61 d2 13 0b 12 09 28 ?? 00 00 0a 16 61 d2 13 0c 07 11 0a 6f ?? 00 00 0a 08 11 0b 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}