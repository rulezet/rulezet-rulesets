rule Trojan_BAT_FormBook_AFB_MTB_32{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 09 2c 5b 00 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 2c 22 00 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 16 } 		$a_03_1 = {0a 0c 2b 33 12 02 28 ?? 00 00 0a 0d 00 02 7b ?? 00 00 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 00 6f } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}