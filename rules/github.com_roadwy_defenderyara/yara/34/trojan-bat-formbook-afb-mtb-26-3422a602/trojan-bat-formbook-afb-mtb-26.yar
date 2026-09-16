rule Trojan_BAT_FormBook_AFB_MTB_26{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 05 11 05 2c 2f 00 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2b 4c 09 16 fe 02 13 06 11 06 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}