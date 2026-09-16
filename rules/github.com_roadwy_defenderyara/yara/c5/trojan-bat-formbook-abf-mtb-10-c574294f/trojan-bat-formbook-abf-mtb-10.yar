rule Trojan_BAT_FormBook_ABF_MTB_10{
	meta:
		description = "Trojan:BAT/FormBook.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 05 6c 5b 28 ?? 00 00 0a 02 7b ?? 01 00 04 5a 13 05 04 2c 11 11 04 04 8e 69 2f 0a 11 05 04 11 04 98 6c 5a 13 05 06 7b ?? 01 00 04 11 04 11 05 28 ?? 00 00 0a a1 11 04 17 58 } 		$a_03_1 = {0a 0a 12 01 fe 15 ?? 00 00 02 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 12 01 12 00 28 ?? 01 00 0a 7d ?? 01 00 04 0e 05 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}