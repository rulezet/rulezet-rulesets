rule Trojan_BAT_FormBook_AF_MTB_13{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 13 05 2b 1a 08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d d9 } 		$a_01_1 = {46 00 6f 00 6c 00 64 00 65 00 72 00 54 00 6f 00 54 00 65 00 78 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}