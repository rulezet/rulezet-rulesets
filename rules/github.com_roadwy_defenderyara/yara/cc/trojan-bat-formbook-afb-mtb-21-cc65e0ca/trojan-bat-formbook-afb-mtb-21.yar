rule Trojan_BAT_FormBook_AFB_MTB_21{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 09 95 11 06 11 0a 95 58 20 ff 00 00 00 5f 13 10 11 07 13 11 09 11 11 91 13 12 11 06 11 10 95 13 13 11 12 11 13 61 13 14 11 05 11 11 11 14 d2 9c 11 07 17 58 } 		$a_01_1 = {41 00 75 00 74 00 6f 00 4e 00 61 00 6a 00 61 00 6d 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}