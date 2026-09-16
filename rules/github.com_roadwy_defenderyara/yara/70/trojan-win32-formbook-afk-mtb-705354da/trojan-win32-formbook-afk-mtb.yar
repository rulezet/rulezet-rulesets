rule Trojan_Win32_FormBook_AFK_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ca 83 e1 0f 42 8a 0c 19 88 4c 02 ff 3b d7 72 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}