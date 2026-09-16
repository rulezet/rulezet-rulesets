rule Trojan_BAT_FormBook_AFB_MTB_24{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 12 02 07 07 61 07 61 03 04 28 ?? 00 00 06 00 07 17 58 0b 07 06 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 } 		$a_03_1 = {16 0a 2b 12 02 06 06 06 5f 60 91 04 28 ?? 00 00 06 00 06 17 58 0a 06 03 03 61 03 61 fe 04 0b 07 2d e2 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}