rule Trojan_BAT_FormBook_ABK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 28 16 0b 2b 0e 02 06 07 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e0 } 		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}