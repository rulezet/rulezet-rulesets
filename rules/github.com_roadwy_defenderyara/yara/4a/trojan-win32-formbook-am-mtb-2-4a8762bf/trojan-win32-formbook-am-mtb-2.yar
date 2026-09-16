rule Trojan_Win32_FormBook_AM_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } 		$a_01_1 = {83 c4 08 89 45 f0 6a 40 68 00 30 00 00 8b 4d f4 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}