rule Trojan_BAT_FormBook_AFR_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 11 04 20 ca 00 00 00 91 20 dd 00 00 00 59 0d 2b c3 02 03 06 04 05 28 ?? ?? ?? 06 06 17 58 0a 19 0d 2b b1 } 		$a_03_1 = {02 03 04 20 a4 02 00 00 20 a6 02 00 00 28 ?? 00 00 2b 0a 0e 04 05 6f ?? 00 00 0a 59 0b 19 0d 2b c5 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}