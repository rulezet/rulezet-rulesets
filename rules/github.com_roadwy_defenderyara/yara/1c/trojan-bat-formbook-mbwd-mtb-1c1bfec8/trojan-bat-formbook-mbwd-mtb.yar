rule Trojan_BAT_FormBook_MBWD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 1f 09 91 1f 16 59 0b } 		$a_01_1 = {64 66 67 66 64 66 67 64 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {65 33 30 37 37 38 66 37 39 38 61 33 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}