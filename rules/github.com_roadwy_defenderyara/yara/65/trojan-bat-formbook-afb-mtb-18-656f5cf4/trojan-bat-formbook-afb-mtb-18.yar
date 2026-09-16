rule Trojan_BAT_FormBook_AFB_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 16 8c ?? 00 00 01 19 8d ?? 00 00 01 25 16 08 16 9a a2 25 17 08 17 9a a2 25 18 20 93 c8 2a 2a 28 ?? 00 00 2b a2 13 0f 11 0f 28 } 		$a_01_1 = {74 68 69 6e 6b 67 65 61 72 5f 66 6f 72 6d } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}