rule Trojan_BAT_FormBook_ABO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 36 06 07 28 ?? 00 00 06 16 0c 2b 15 07 08 28 ?? 00 00 06 02 07 08 03 04 28 ?? 00 00 06 08 17 58 0c 08 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 d9 } 		$a_03_1 = {0a 02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 28 ?? 00 00 06 07 05 28 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}