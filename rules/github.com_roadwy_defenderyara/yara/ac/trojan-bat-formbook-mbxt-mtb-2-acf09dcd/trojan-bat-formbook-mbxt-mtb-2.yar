rule Trojan_BAT_FormBook_MBXT_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 64 61 64 73 61 64 73 61 64 73 61 64 61 } 		$a_01_1 = {63 63 63 63 63 63 63 63 63 63 32 31 32 33 31 32 33 } 		$a_01_2 = {4b 00 6f 00 72 00 65 00 61 00 6e 00 43 00 68 00 65 00 73 00 73 00 } 		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}