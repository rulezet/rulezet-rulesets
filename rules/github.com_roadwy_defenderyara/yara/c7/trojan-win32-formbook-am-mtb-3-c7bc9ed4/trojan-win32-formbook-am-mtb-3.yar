rule Trojan_Win32_FormBook_AM_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 00 8b 04 88 2d d6 4b 04 00 41 } 		$a_01_1 = {88 04 33 43 81 fb 6c 07 00 00 7c ef } 		$a_01_2 = {53 69 6d 70 53 68 61 6e 67 68 61 69 } 		$a_01_3 = {48 61 72 71 75 65 62 75 73 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}