rule Trojan_BAT_FormBook_AFB_MTB_22{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 3d 00 09 11 06 11 05 6f ?? 00 00 0a 17 59 2e 18 11 05 11 06 6f ?? 00 00 0a 08 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 09 11 05 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 06 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}