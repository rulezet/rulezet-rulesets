rule Trojan_BAT_FormBook_AFB_MTB_28{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 69 00 02 09 11 06 28 ?? 00 00 06 13 07 02 11 06 08 28 ?? 00 00 06 13 08 02 07 11 08 08 28 ?? 00 00 06 13 09 02 07 11 06 08 11 07 11 09 28 ?? 00 00 06 13 0a 02 11 0a 28 } 		$a_01_1 = {4a 00 61 00 70 00 61 00 6e 00 65 00 73 00 65 00 54 00 72 00 61 00 69 00 6e 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}