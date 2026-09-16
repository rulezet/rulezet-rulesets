rule Trojan_Win32_FormBook_EB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c8 fe c0 fe c0 fe c0 34 6b fe c0 2c 1c fe c0 fe c0 fe c0 34 7f 04 71 fe c0 2c 57 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}