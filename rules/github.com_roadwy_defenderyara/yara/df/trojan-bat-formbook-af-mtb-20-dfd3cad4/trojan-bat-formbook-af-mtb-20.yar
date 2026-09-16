rule Trojan_BAT_FormBook_AF_MTB_20{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 16 13 07 2b 61 11 05 11 07 6f ?? ?? ?? 0a 1f 77 33 06 11 04 17 59 13 04 11 05 11 07 6f ?? ?? ?? 0a 1f 61 33 04 09 17 59 0d 11 05 11 07 6f ?? ?? ?? 0a 1f 73 33 06 11 04 17 58 13 04 11 05 11 07 6f ?? ?? ?? 0a 1f 64 33 04 09 17 58 0d 02 } 		$a_01_1 = {54 00 6f 00 77 00 65 00 72 00 20 00 44 00 65 00 66 00 65 00 6e 00 73 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}