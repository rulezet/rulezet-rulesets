rule Trojan_BAT_FormBook_AFB_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 05 11 05 28 ?? ?? ?? 06 13 06 07 06 11 06 d2 9c 00 11 04 17 58 } 		$a_01_1 = {53 00 6b 00 79 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}