rule Trojan_BAT_FormBook_AMA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 59 0b 07 16 31 33 07 17 32 0d 03 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 07 18 32 0d 03 12 00 28 ?? 00 00 0a 6f ?? 00 00 0a 07 19 33 0d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}