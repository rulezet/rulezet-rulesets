rule Trojan_Win32_FormBook_AFB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 ff d6 68 ?? ?? ?? ?? 53 a3 08 c9 43 00 ff d7 50 ff d6 68 ?? ?? ?? ?? 53 a3 0c c9 43 00 ff d7 50 ff d6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}