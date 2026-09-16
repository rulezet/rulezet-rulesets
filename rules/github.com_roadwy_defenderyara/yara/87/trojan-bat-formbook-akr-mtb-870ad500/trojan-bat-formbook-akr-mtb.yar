rule Trojan_BAT_FormBook_AKR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 17 5f 0d 2b 60 07 18 5f 17 63 13 04 2b 3f 06 02 09 11 04 6f ?? 01 00 06 13 05 04 03 6f ?? 00 00 0a 59 13 06 11 06 19 28 ?? 00 00 06 2c 0a 03 11 05 28 ?? 00 00 06 2b 0f 11 06 16 31 0a 03 11 05 11 06 28 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}