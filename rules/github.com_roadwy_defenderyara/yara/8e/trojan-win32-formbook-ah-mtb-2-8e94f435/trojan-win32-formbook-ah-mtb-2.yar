rule Trojan_Win32_FormBook_AH_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 [0-10] 66 0f 74 c1 [0-10] 66 0f 6e e6 [0-10] 66 0f 6e e9 [0-10] 0f 57 ec [0-10] 66 0f 7e e9 [0-10] 39 c1 [0-10] 90 13 0f 77 [0-10] 46 [0-10] 8b 0f } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}