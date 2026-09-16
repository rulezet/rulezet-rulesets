rule Trojan_BAT_FormBook_AF_MTB_9{
	meta:
		description = "Trojan:BAT/FormBook.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 14 18 8d 01 00 00 01 25 16 09 74 07 00 00 01 28 ?? ?? ?? 06 17 9a a2 25 17 11 04 a2 28 } 		$a_01_1 = {50 00 61 00 72 00 73 00 65 00 72 00 41 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}