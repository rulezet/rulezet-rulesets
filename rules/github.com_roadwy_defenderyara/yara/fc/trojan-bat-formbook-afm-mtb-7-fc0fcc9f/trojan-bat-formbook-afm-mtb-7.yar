rule Trojan_BAT_FormBook_AFM_MTB_7{
	meta:
		description = "Trojan:BAT/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 06 6f 7e 00 00 0a 03 73 7f 00 00 0a 0b de 14 0c 08 6f 73 00 00 0a 73 5f 00 00 06 73 80 00 00 0a 0b de } 		$a_01_1 = {0a 07 03 6f 9b 00 00 06 07 06 6f 6c 00 00 0a 6f 9d 00 00 06 07 06 6f 79 00 00 0a 6f a3 00 00 06 07 06 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}