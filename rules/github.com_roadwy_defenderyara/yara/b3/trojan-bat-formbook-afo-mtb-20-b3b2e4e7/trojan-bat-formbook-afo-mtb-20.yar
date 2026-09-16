rule Trojan_BAT_FormBook_AFO_MTB_20{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 19 32 50 12 00 28 ?? 00 00 0a 1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 19 8d ?? 00 00 01 25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e } 		$a_03_1 = {16 0a 2b 28 16 0b 2b 0e 02 03 06 07 04 28 ?? 00 00 06 07 17 58 0b 07 02 28 ?? 00 00 06 2f 09 03 6f ?? 00 00 0a 04 32 e0 06 17 58 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}