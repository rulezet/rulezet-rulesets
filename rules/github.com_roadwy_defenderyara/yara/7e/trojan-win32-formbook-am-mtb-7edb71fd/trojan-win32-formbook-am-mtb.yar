rule Trojan_Win32_FormBook_AM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc } 		$a_01_1 = {89 45 f4 6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}