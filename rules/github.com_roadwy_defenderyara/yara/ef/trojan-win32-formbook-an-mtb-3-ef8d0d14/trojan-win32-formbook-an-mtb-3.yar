rule Trojan_Win32_FormBook_AN_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 83 c0 01 89 45 08 8b 4d 08 0f be 11 85 d2 74 16 8b 45 fc c1 e0 05 03 45 fc 8b 4d 08 0f be 11 03 c2 89 45 fc eb d7 } 		$a_01_1 = {89 4d f4 8b 55 f8 8b 45 08 03 42 24 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}