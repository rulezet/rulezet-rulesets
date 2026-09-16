rule Trojan_BAT_FormBook_MBXT_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 00 38 00 46 00 57 00 37 00 43 00 34 00 38 00 45 00 46 00 42 00 48 00 35 00 38 00 43 00 39 00 5a 00 46 00 35 00 37 00 31 00 34 00 } 		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 } 		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=16
 
}