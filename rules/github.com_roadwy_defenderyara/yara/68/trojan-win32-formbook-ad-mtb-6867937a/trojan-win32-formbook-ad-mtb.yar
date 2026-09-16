rule Trojan_Win32_FormBook_AD_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 [0-10] 66 0f 74 c1 [0-10] 66 0f 6e e6 [0-10] 66 0f 6e e9 [0-10] 66 0f 57 ec [0-10] 66 0f 7e e9 [0-10] 39 c1 74 } 		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}