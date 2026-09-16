rule Trojan_BAT_FormBook_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 07 00 00 06 0a 73 0a 00 00 0a 25 06 28 05 00 00 06 6f 0b 00 00 0a 0b dd 08 } 		$a_01_1 = {02 03 1f 1f 5f 63 02 1e 03 59 1f 1f 5f 62 60 d2 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}