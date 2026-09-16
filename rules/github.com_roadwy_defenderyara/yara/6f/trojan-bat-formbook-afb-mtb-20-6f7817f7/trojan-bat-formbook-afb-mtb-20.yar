rule Trojan_BAT_FormBook_AFB_MTB_20{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 16 0b 18 0d 2b d6 02 07 06 03 04 28 ?? 00 00 06 0a 07 17 58 0b 18 0d 2b c3 } 		$a_03_1 = {11 05 17 58 20 ff 00 00 00 5f 13 05 11 06 11 04 75 ?? 00 00 1b 11 05 95 58 20 ff 00 00 00 5f 13 06 1f 1c 13 12 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}