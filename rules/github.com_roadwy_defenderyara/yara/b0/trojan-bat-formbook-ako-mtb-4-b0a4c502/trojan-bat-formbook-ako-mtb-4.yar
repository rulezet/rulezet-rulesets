rule Trojan_BAT_FormBook_AKO_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 01 00 0a 13 04 04 03 6f ?? 01 00 0a 59 13 05 11 05 19 32 29 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 2b 47 11 05 16 31 42 19 8d ?? 00 00 01 25 16 12 04 28 ?? 01 00 0a 9c 25 17 12 04 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}