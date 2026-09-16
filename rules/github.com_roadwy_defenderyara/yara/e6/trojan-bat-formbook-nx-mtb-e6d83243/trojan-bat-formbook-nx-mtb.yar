rule Trojan_BAT_FormBook_NX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {05 0e 04 06 58 03 04 06 58 91 9c 06 17 58 0a 06 0e 05 32 ec 2a } 		$a_03_1 = {06 07 02 7b ?? 00 00 04 07 94 9e 07 17 58 0b 07 02 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}