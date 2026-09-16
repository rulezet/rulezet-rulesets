rule Trojan_Win32_FormBook_C_MTB{
	meta:
		description = "Trojan:Win32/FormBook.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e9 04 ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 04 0f f7 da f8 11 d1 7d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}