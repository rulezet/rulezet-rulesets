rule Trojan_BAT_FormBook_AF_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 20 2b 28 00 11 1e 11 20 18 6f ?? ?? ?? 0a 20 03 02 00 00 28 ?? ?? ?? 0a 13 22 11 1f 11 22 6f ?? ?? ?? 0a 00 11 20 18 58 13 20 00 11 20 11 1e 6f ?? ?? ?? 0a fe 04 13 23 11 23 2d c7 } 		$a_01_1 = {65 00 76 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 53 00 6f 00 63 00 63 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}